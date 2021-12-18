package tools

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func ReadBase64File(filename string) ([]byte, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))

	var sb strings.Builder
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
	}
	data := sb.String()

	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, []byte(data))
	if err != nil {
		fmt.Println("decode error:", err)
		return nil, err
	}
	dst = dst[:n]
	return dst, nil
}
