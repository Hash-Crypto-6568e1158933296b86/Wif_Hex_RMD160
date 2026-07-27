package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/ripemd160"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Base58 alphabet
var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// base58Decode decodes a base58-encoded string to bytes (no checksum removal).
func base58Decode(input string) ([]byte, error) {
	result := big.NewInt(0)
	for _, ch := range []byte(input) {
		idx := bytes.IndexByte(b58Alphabet, ch)
		if idx < 0 {
			return nil, fmt.Errorf("caractere inválido base58: %q", ch)
		}
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(idx)))
	}
	decoded := result.Bytes()

	// restore leading zeros (encoded as '1')
	pad := 0
	for i := 0; i < len(input) && input[i] == '1'; i++ {
		pad++
	}
	return append(bytes.Repeat([]byte{0x00}, pad), decoded...), nil
}

// base58Encode encodes bytes to base58 string.
func base58Encode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	var result []byte
	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := new(big.Int)

	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append([]byte{b58Alphabet[int(mod.Int64())]}, result...)
	}

	// add '1' for each leading 0x00
	for _, b := range input {
		if b == 0x00 {
			result = append([]byte{'1'}, result...)
		} else {
			break
		}
	}

	return string(result)
}

// wifToHex parses a WIF and returns the private key hex and whether it's compressed.
func wifToHex(wif string) (string, bool, error) {
	decoded, err := base58Decode(wif)
	if err != nil {
		return "", false, err
	}

	// decoded should be: 1 (version) + 32 (priv) [+1 (0x01 if compressed)] + 4 (checksum)
	if len(decoded) != 37 && len(decoded) != 38 {
		return "", false, errors.New("formato WIF inválido (tamanho inesperado)")
	}

	// verify version byte (0x80 for mainnet)
	if decoded[0] != 0x80 {
		return "", false, errors.New("prefixo WIF inválido (não é mainnet)")
	}

	// verify checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(checksum, h2[:4]) {
		return "", false, errors.New("checksum WIF inválido")
	}

	var privBytes []byte
	compressed := false
	if len(payload) == 34 && payload[33] == 0x01 { // 1 + 32 + 1
		privBytes = payload[1:33]
		compressed = true
	} else if len(payload) == 33 { // 1 + 32
		privBytes = payload[1:33]
	} else {
		return "", false, errors.New("formato WIF inválido (payload)")
	}

	return hex.EncodeToString(privBytes), compressed, nil
}

// hexToWIF converts a hex private key to WIF format
func hexToWIF(hexKey string, compressed bool) (string, error) {
	privBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	if len(privBytes) != 32 {
		return "", errors.New("chave privada deve ter 32 bytes")
	}

	// Add version byte (0x80 for mainnet)
	payload := append([]byte{0x80}, privBytes...)

	// Add compression flag if needed
	if compressed {
		payload = append(payload, 0x01)
	}

	// Calculate checksum
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	checksum := h2[:4]

	// Combine payload and checksum
	full := append(payload, checksum...)

	// Encode to base58
	wif := base58Encode(full)
	return wif, nil
}

// privateKeyToPublicKey uses secp256k1 to derive public key bytes (compressed or not).
func privateKeyToPublicKey(hexKey string, compressed bool) ([]byte, error) {
	privBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	// ensure 32 bytes
	if len(privBytes) != 32 {
		// left-pad with zeros if needed
		if len(privBytes) < 32 {
			pad := make([]byte, 32-len(privBytes))
			privBytes = append(pad, privBytes...)
		} else {
			return nil, errors.New("chave privada tamanho inválido")
		}
	}

	privKey := secp256k1.PrivKeyFromBytes(privBytes)
	pubKey := privKey.PubKey()

	if compressed {
		return pubKey.SerializeCompressed(), nil
	}
	return pubKey.SerializeUncompressed(), nil
}

// publicKeyToAddress computes Bitcoin P2PKH address (mainnet) from public key bytes.
func publicKeyToAddress(pubKey []byte) (string, error) {
	sha := sha256.Sum256(pubKey)
	rip := ripemd160.New()
	_, err := rip.Write(sha[:])
	if err != nil {
		return "", err
	}
	pubKeyHash := rip.Sum(nil) // 20 bytes

	// version byte 0x00 for mainnet
	versioned := append([]byte{0x00}, pubKeyHash...)

	// checksum
	h1 := sha256.Sum256(versioned)
	h2 := sha256.Sum256(h1[:])
	checksum := h2[:4]

	full := append(versioned, checksum...)
	addr := base58Encode(full)
	return addr, nil
}

// bech32Charset é o alfabeto usado pela codificação Bech32 (BIP173).
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Polymod calcula o checksum polinomial usado pelo Bech32.
func bech32Polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := byte(chk >> 25)
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expande o human-readable part (ex: "bc") para uso no checksum.
func bech32HRPExpand(hrp string) []byte {
	result := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, byte(c)>>5)
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, byte(c)&31)
	}
	return result
}

// bech32VerifyChecksum verifica se o checksum do endereço é válido.
func bech32VerifyChecksum(hrp string, data []byte) bool {
	values := append(bech32HRPExpand(hrp), data...)
	return bech32Polymod(values) == 1
}

// bech32Decode decodifica uma string Bech32, retornando o HRP e os dados (5-bit groups, sem checksum).
func bech32Decode(input string) (string, []byte, error) {
	if len(input) < 8 || len(input) > 90 {
		return "", nil, errors.New("comprimento inválido para endereço bech32")
	}

	lower := strings.ToLower(input)
	upper := strings.ToUpper(input)
	if input != lower && input != upper {
		return "", nil, errors.New("mistura inválida de maiúsculas e minúsculas em bech32")
	}
	input = lower

	pos := strings.LastIndex(input, "1")
	if pos < 1 || pos+7 > len(input) {
		return "", nil, errors.New("separador '1' não encontrado ou posição inválida")
	}

	hrp := input[:pos]
	dataPart := input[pos+1:]

	data := make([]byte, 0, len(dataPart))
	for _, c := range dataPart {
		idx := strings.IndexRune(bech32Charset, c)
		if idx < 0 {
			return "", nil, fmt.Errorf("caractere inválido em bech32: %q", c)
		}
		data = append(data, byte(idx))
	}

	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, errors.New("checksum bech32 inválido")
	}

	// remove os 6 últimos símbolos (checksum)
	return hrp, data[:len(data)-6], nil
}

// convertBits reagrupa bits entre tamanhos diferentes (ex: 5-bit → 8-bit).
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	var result []byte
	maxv := uint32(1<<toBits) - 1

	for _, value := range data {
		if uint32(value)>>fromBits != 0 {
			return nil, errors.New("valor fora do intervalo em convertBits")
		}
		acc = (acc << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || (acc<<(toBits-bits))&maxv != 0 {
		return nil, errors.New("padding inválido em convertBits")
	}

	return result, nil
}

// segwitAddressToRMD160 decodifica um endereço SegWit nativo (bech32, ex: BIP84 "bc1q...")
// e retorna o hash de 20 bytes (RIPEMD-160(SHA-256(pubKey)) para P2WPKH) em hex.
func segwitAddressToRMD160(address string) (string, int, error) {
	hrp, data, err := bech32Decode(address)
	if err != nil {
		return "", 0, err
	}

	if hrp != "bc" && hrp != "tb" {
		return "", 0, fmt.Errorf("prefixo bech32 desconhecido: %q (esperado 'bc' ou 'tb')", hrp)
	}

	if len(data) < 1 {
		return "", 0, errors.New("dados bech32 vazios")
	}

	witnessVersion := int(data[0])
	program, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return "", 0, err
	}

	if witnessVersion == 0 && len(program) != 20 && len(program) != 32 {
		return "", 0, errors.New("tamanho de programa inválido para witness v0")
	}

	if witnessVersion != 0 {
		return "", 0, fmt.Errorf("versão de witness %d não suportada para BIP84 (esperado 0)", witnessVersion)
	}

	if len(program) != 20 {
		return "", 0, errors.New("endereço não é P2WPKH (BIP84) — tamanho de hash diferente de 20 bytes")
	}

	return hex.EncodeToString(program), witnessVersion, nil
}

// addressToRMD160 decodes a base58check Bitcoin address (P2PKH ou P2SH) e
// retorna o hash RIPEMD-160 (pubKeyHash/scriptHash) em hex, junto com o byte
// de versão encontrado.
func addressToRMD160(address string) (string, byte, error) {
	decoded, err := base58Decode(address)
	if err != nil {
		return "", 0, err
	}

	// esperado: 1 (versão) + 20 (hash) + 4 (checksum) = 25 bytes
	if len(decoded) != 25 {
		return "", 0, errors.New("endereço inválido (tamanho decodificado incorreto)")
	}

	payload := decoded[:21]
	checksum := decoded[21:]

	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(checksum, h2[:4]) {
		return "", 0, errors.New("checksum do endereço inválido")
	}

	version := payload[0]
	hash160 := payload[1:]

	return hex.EncodeToString(hash160), version, nil
}

// publicKeyToRIPEMD160 returns the RIPEMD-160(SHA-256(pubKey)) hash as hex.
func publicKeyToRIPEMD160(pubKey []byte) (string, error) {
	sha := sha256.Sum256(pubKey)
	rip := ripemd160.New()
	_, err := rip.Write(sha[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rip.Sum(nil)), nil
}

// saveToCSV saves the conversion result to a CSV file
func saveToCSV(operation, input, output string) error {
	file, err := os.OpenFile("Result.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if file is empty
	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		header := []string{"Operação", "Entrada", "Saída"}
		if err := writer.Write(header); err != nil {
			return err
		}
	}

	record := []string{operation, input, output}
	return writer.Write(record)
}

func main() {
	fmt.Println("=== Conversor Bitcoin Keys ===")
	fmt.Println("1 - WIF → Hex")
	fmt.Println("2 - Hex → WIF")
	fmt.Println("3 - Endereço (P2PKH/P2SH) → RIPEMD-160")
	fmt.Println("4 - Endereço BIP84 (bc1q...) → RIPEMD-160")
	fmt.Print("Escolha a função (1, 2, 3 ou 4): ")

	var choice string
	fmt.Scanln(&choice)

	switch choice {
	case "1":
		fmt.Print("Digite a chave WIF: ")
		var wif string
		fmt.Scanln(&wif)

		hexKey, compressed, err := wifToHex(wif)
		if err != nil {
			fmt.Println("Erro ao converter WIF:", err)
			return
		}

		// Generate additional info
		pubKey, err := privateKeyToPublicKey(hexKey, compressed)
		if err != nil {
			fmt.Println("Erro ao gerar chave pública:", err)
			return
		}

		addr, err := publicKeyToAddress(pubKey)
		if err != nil {
			fmt.Println("Erro ao gerar endereço:", err)
			return
		}

		rmd160, err := publicKeyToRIPEMD160(pubKey)
		if err != nil {
			fmt.Println("Erro ao gerar RIPEMD-160:", err)
			return
		}

		fmt.Println("\n=== RESULTADO ===")
		fmt.Println("Chave Privada (hex):", hexKey)
		fmt.Println("Formato WIF:", map[bool]string{true: "Comprimido", false: "Não comprimido"}[compressed])
		fmt.Println("Chave Pública (hex):", hex.EncodeToString(pubKey))
		fmt.Println("RIPEMD-160(SHA-256(pubKey)):", rmd160)
		fmt.Println("Endereço Bitcoin (P2PKH):", addr)

		// Save to CSV
		if err := saveToCSV("WIF_to_Hex", wif, hexKey); err != nil {
			fmt.Println("Erro ao salvar no CSV:", err)
		} else {
			fmt.Println("Resultado salvo em Result.csv")
		}

	case "2":
		fmt.Print("Digite a chave Hex (64 caracteres): ")
		var hexKey string
		fmt.Scanln(&hexKey)

		// Clean input
		hexKey = strings.TrimSpace(hexKey)
		hexKey = strings.ToLower(hexKey)

		if len(hexKey) != 64 {
			fmt.Println("Erro: A chave hex deve ter exatamente 64 caracteres")
			return
		}

		fmt.Print("Formato comprimido? (s/n): ")
		var comp string
		fmt.Scanln(&comp)

		compressed := strings.ToLower(comp) == "s" || strings.ToLower(comp) == "y"

		wif, err := hexToWIF(hexKey, compressed)
		if err != nil {
			fmt.Println("Erro ao converter Hex para WIF:", err)
			return
		}

		// Generate additional info
		pubKey, err := privateKeyToPublicKey(hexKey, compressed)
		if err != nil {
			fmt.Println("Erro ao gerar chave pública:", err)
			return
		}

		addr, err := publicKeyToAddress(pubKey)
		if err != nil {
			fmt.Println("Erro ao gerar endereço:", err)
			return
		}

		rmd160, err := publicKeyToRIPEMD160(pubKey)
		if err != nil {
			fmt.Println("Erro ao gerar RIPEMD-160:", err)
			return
		}

		fmt.Println("\n=== RESULTADO ===")
		fmt.Println("Chave WIF:", wif)
		fmt.Println("Formato:", map[bool]string{true: "Comprimido", false: "Não comprimido"}[compressed])
		fmt.Println("Chave Pública (hex):", hex.EncodeToString(pubKey))
		fmt.Println("RIPEMD-160(SHA-256(pubKey)):", rmd160)
		fmt.Println("Endereço Bitcoin (P2PKH):", addr)

		// Save to CSV
		if err := saveToCSV("Hex_to_WIF", hexKey, wif); err != nil {
			fmt.Println("Erro ao salvar no CSV:", err)
		} else {
			fmt.Println("Resultado salvo em Result.csv")
		}

	case "3":
		fmt.Print("Digite o endereço Bitcoin: ")
		var address string
		fmt.Scanln(&address)
		address = strings.TrimSpace(address)

		rmd160, version, err := addressToRMD160(address)
		if err != nil {
			fmt.Println("Erro ao converter endereço:", err)
			return
		}

		tipo := "Desconhecido"
		switch version {
		case 0x00:
			tipo = "P2PKH (mainnet)"
		case 0x05:
			tipo = "P2SH (mainnet)"
		case 0x6f:
			tipo = "P2PKH (testnet)"
		case 0xc4:
			tipo = "P2SH (testnet)"
		}

		fmt.Println("\n=== RESULTADO ===")
		fmt.Println("Endereço:", address)
		fmt.Println("Tipo:", tipo)
		fmt.Println("RIPEMD-160:", rmd160)

		// Save to CSV
		if err := saveToCSV("Address_to_RMD160", address, rmd160); err != nil {
			fmt.Println("Erro ao salvar no CSV:", err)
		} else {
			fmt.Println("Resultado salvo em Result.csv")
		}

	case "4":
		fmt.Print("Digite o endereço BIP84 (bc1q...): ")
		var address string
		fmt.Scanln(&address)
		address = strings.TrimSpace(address)

		rmd160, witnessVersion, err := segwitAddressToRMD160(address)
		if err != nil {
			fmt.Println("Erro ao converter endereço BIP84:", err)
			return
		}

		fmt.Println("\n=== RESULTADO ===")
		fmt.Println("Endereço:", address)
		fmt.Println("Tipo: P2WPKH (BIP84, witness v", witnessVersion, ")")
		fmt.Println("RIPEMD-160:", rmd160)

		// Save to CSV
		if err := saveToCSV("BIP84_Address_to_RMD160", address, rmd160); err != nil {
			fmt.Println("Erro ao salvar no CSV:", err)
		} else {
			fmt.Println("Resultado salvo em Result.csv")
		}

	default:
		fmt.Println("Opção inválida! Escolha 1, 2, 3 ou 4.")
		return
	}
}
