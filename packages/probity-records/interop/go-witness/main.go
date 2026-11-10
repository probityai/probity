// Command go-witness is a c2sp.org/tlog-witness add-checkpoint endpoint built only from libraries
// that are not ours: golang.org/x/mod/sumdb/note (signed notes, the log's Ed25519 signature),
// github.com/transparency-dev/formats/note (cosignature/v1) and github.com/transparency-dev/merkle
// (RFC 9162 consistency proofs). It is the external node the probity-records checkpoint feed must
// complete the handshake with; interop.py drives it.
//
// Usage: go-witness -log-vkey <vkey> -name <witness name> -seed <hex> -listen 127.0.0.1:PORT
// It prints its cosignature vkey on the first line of stdout, then serves.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

type state struct {
	mu   sync.Mutex
	size uint64
	root []byte
}

func main() {
	logVKey := flag.String("log-vkey", "", "the log's Ed25519 vkey")
	name := flag.String("name", "customer.example/go-witness", "witness name")
	seedHex := flag.String("seed", "", "32-byte hex seed of the witness key")
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	flag.Parse()
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("seed must be 32 bytes of hex")
	}
	_, vkey, err := note.GenerateKey(bytes.NewReader(seed), *name)
	must(err)
	cvkey, err := fnote.VKeyToCosignatureV1(vkey)
	must(err)
	skey := fmt.Sprintf("PRIVATE+KEY+%s+00000000+%s", *name,
		base64.StdEncoding.EncodeToString(append([]byte{0x04}, seed...)))
	signer, err := fnote.NewSignerForCosignatureV1(skey)
	must(err)
	verifier, err := note.NewVerifier(*logVKey)
	must(err)
	origin := strings.SplitN(*logVKey, "+", 2)[0]
	st := &state{root: rfc6962.DefaultHasher.EmptyRoot()}
	fmt.Println(cvkey)
	os.Stdout.Sync()
	http.HandleFunc("/add-checkpoint", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		head, rest, ok := bytes.Cut(body, []byte("\n\n"))
		if !ok {
			http.Error(w, "malformed", 400)
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(head))
		sc.Scan()
		oldText, found := strings.CutPrefix(sc.Text(), "old ")
		if !found {
			http.Error(w, "no old line", 400)
			return
		}
		old, err := strconv.ParseUint(oldText, 10, 64)
		if err != nil {
			http.Error(w, "old", 400)
			return
		}
		var hashes [][]byte
		for sc.Scan() {
			h, err := base64.StdEncoding.DecodeString(sc.Text())
			if err != nil || len(h) != 32 {
				http.Error(w, "proof line", 400)
				return
			}
			hashes = append(hashes, h)
		}
		n, err := note.Open(rest, note.VerifierList(verifier))
		if err != nil {
			http.Error(w, "log signature: "+err.Error(), 403)
			return
		}
		lines := strings.Split(strings.TrimSuffix(n.Text, "\n"), "\n")
		if len(lines) < 3 || lines[0] != origin {
			http.Error(w, "unknown origin", 404)
			return
		}
		size, err := strconv.ParseUint(lines[1], 10, 64)
		root, err2 := base64.StdEncoding.DecodeString(lines[2])
		if err != nil || err2 != nil || len(root) != 32 {
			http.Error(w, "checkpoint", 400)
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		if old != st.size {
			w.Header().Set("Content-Type", "text/x.tlog.size")
			w.WriteHeader(409)
			fmt.Fprintf(w, "%d\n", st.size)
			return
		}
		switch {
		case old > size:
			http.Error(w, "old past size", 400)
			return
		case old == size:
			if !bytes.Equal(root, st.root) || len(hashes) != 0 {
				http.Error(w, "split view", 422)
				return
			}
		case old > 0:
			if err := proof.VerifyConsistency(rfc6962.DefaultHasher, old, size, hashes, st.root, root); err != nil {
				http.Error(w, "consistency: "+err.Error(), 422)
				return
			}
		}
		signed, err := note.Sign(&note.Note{Text: n.Text}, signer)
		if err != nil {
			http.Error(w, "sign", 500)
			return
		}
		_, sigs, _ := bytes.Cut(signed, []byte("\n\n"))
		st.size, st.root = size, root
		w.Write(sigs)
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
