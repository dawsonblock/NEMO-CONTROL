package main
import("fmt";"crypto/sha256";"encoding/base64")
func main(){p:=[]byte("[]");fmt.Printf("{\"registry_sha256\":\"%x\",\"canonical_payload\":\"%s\"}\n",sha256.Sum256(p),base64.StdEncoding.EncodeToString(p))}
