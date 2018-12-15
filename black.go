// Package black provides functions for solving cryptopals challanges.
// https://cryptopals.com
package main

import (
    "bufio"
    "bytes"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
    "unicode"
)

var englishLanguageCharactedExpectedFrequencies = []float64{
    0.0651738, 0.0124248, 0.0217339, 0.0349835,
    0.1041442, 0.0197881, 0.0158610, 0.0492888,
    0.0558094, 0.0009033, 0.0050529, 0.0331490,
    0.0202124, 0.0564513, 0.0596302, 0.0137645,
    0.0008606, 0.0497563, 0.0515760, 0.0729357,
    0.0225134, 0.0082903, 0.0171272, 0.0013692,
    0.0145984, 0.0007836, 0.1918182,
}

func main() {
    fmt.Println(BreakRepeatingKeyXOR("samples/6.txt"))
}

// ConvertHexToBase64 converts a hex string to its base64 encoding,
// returning base64 string and error(if any).
func ConvertHexToBase64(input string) (string, error) {
    raw, err := hex.DecodeString(input)
    if err != nil {
        return "", err
    }
    output := base64.StdEncoding.EncodeToString([]byte(raw))
    return output, err
}

// FixedXOR takes two hex value and returns the hex representation of their
// that results from their bitwise XOR
func FixedXOR(hexValueOne string, hexValueTwo string) (string, error) {
    rawOne, err := hex.DecodeString(hexValueOne)
    if err != nil {
        return "", err
    }
    rawTwo, err := hex.DecodeString(hexValueTwo)
    if err != nil {
        return "", err
    }
    rawResult, err := XORBytes(rawOne, rawTwo)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(rawResult), err
}

// XORBytes returns the bitwise XOR of top and bottom byte slices,
// returning the XOR result or error if provided byte slices are not equal length
func XORBytes(top []byte, bottom []byte) ([]byte, error) {
    if len(top) != len(bottom) {
        return []byte{}, errors.New("Provided byte buffers must be of the same length.")
    }
    xORed := make([]byte, len(top))
    for bit := range top {
        xORed[bit] = top[bit] ^ bottom[bit]
    }
    return xORed, nil
}

// SingleByteXor returns the result of bitwise XOR using
// xor on input.
func SingleByteXor(input []byte, xor byte) []byte {
    xORed := make([]byte, len(input))
    for bit := range input {
        xORed[bit] = input[bit] ^ xor
    }
    return xORed
}

// https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
func TextEnglishnessScore(input string) float64 {
    uppercaseInput := strings.ToUpper(input)
    englishCharacterCount := len(englishLanguageCharactedExpectedFrequencies)
    matchedCharacterCounters := make([]int, englishCharacterCount)
    matchedCharactersFrequencies := make([]float64, englishCharacterCount)
    var totalMatched int

    for _, character := range uppercaseInput {
        characterIndex := int(character - 'A')
        if characterIndex > 0 && characterIndex < 26 {
            matchedCharacterCounters[characterIndex]++
            totalMatched++
        }
        if unicode.IsSpace(character) {
            matchedCharacterCounters[26]++
            totalMatched++
        }
    }
    if totalMatched == 0 {
        return float64(totalMatched)
    }
    var chiSquaredScore float64
    for i := 0; i < englishCharacterCount; i++ {
        matchedCharactersFrequencies[i] = float64(matchedCharacterCounters[i]) / float64(totalMatched)
        chiSquaredScore += (matchedCharactersFrequencies[i] - englishLanguageCharactedExpectedFrequencies[i]) * (matchedCharactersFrequencies[i] - englishLanguageCharactedExpectedFrequencies[i]) / (englishLanguageCharactedExpectedFrequencies[i])
    }
    return chiSquaredScore
}

func BreakSingleXORCipher(hexValue string) (decoded string, cipherKey string, err error) {
    bestEnglishScore := 100.0
    var bestGuessCipher string
    var bestGuessDecoded string
    raw, err := hex.DecodeString(hexValue)
    if err != nil {
        return decoded, cipherKey, err
    }
    // Hex value = 8 bits = 2^8= 256 possible hex values
    for guessCipher := 0; guessCipher <= 255; guessCipher++ {
        decoded := SingleByteXor(raw, byte(guessCipher))
        score := TextEnglishnessScore(string(decoded))
        // fmt.Println(guessCipher, score, string(decoded))
        if score > 0 && score < bestEnglishScore {
            bestEnglishScore = score
            bestGuessCipher = string(byte(guessCipher))
            bestGuessDecoded = string(decoded)
        }
    }
    return bestGuessDecoded, bestGuessCipher, err
}

type SingleXorGuess struct {
    Decoded   string
    CipherKey string
    Score     float64
}

func DetectSingleXOR(filepath string) []SingleXorGuess {
    var singleXorGuesses []SingleXorGuess
    file, err := os.Open(filepath)
    if err != nil {
        return singleXorGuesses
    }
    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)
    for scanner.Scan() {
        encodedLine := scanner.Text()
        decoded, cipherKey, err := BreakSingleXORCipher(encodedLine)
        if err != nil {
            continue
        }
        score := TextEnglishnessScore(decoded)
        guess := SingleXorGuess{Decoded: decoded,
            CipherKey: cipherKey,
            Score:     score}
        singleXorGuesses = append(singleXorGuesses, guess)
    }
    return singleXorGuesses
}

func RepeatingKeyXOR(value string, key string) string {
    var currentkeyIndex int
    rawValue := []byte(value)
    rawResult := make([]byte, len(rawValue))
    rawKey := []byte(key)
    keyLength := len(rawKey)
    for index, valueBit := range rawValue {
        rawResult[index] = valueBit ^ rawKey[currentkeyIndex]
        currentkeyIndex++
        currentkeyIndex = currentkeyIndex % keyLength
    }
    return hex.EncodeToString(rawResult)
}

// HammmingDistance returns the hamming distance between two byte arrays.
// https://en.wikipedia.org/wiki/Hamming_distance
func HammingDistance(top, bottom []byte) int {
    var distance int
    for bit := range top {
        // Perform an xor to see if the current bytes of top are the same
        innerBit := top[bit] ^ bottom[bit]
        for innerBit > 0 {
            if innerBit&1 == 1 {
                distance++
            }
            // Remove the top bit we just checked to get to the next
            innerBit = innerBit >> 1
        }
    }
    return distance
}

func BreakRepeatingKeyXOR(base64EncodedFilePath string) int {
    var bestGuessKeySize int
    bestHammingDistance := 1000
    // There's a file here.
    // It's been base64'd after being encrypted with repeating-key XOR.
    // Decrypt it.
    file, err := os.Open(base64EncodedFilePath)
    if err != nil {
        return 0
    }
    base64Content, err := ioutil.ReadAll(file)
    if err != nil {
        return 1
    }
    // fmt.Println(string(base64Content))
    rawContent, err := base64.StdEncoding.DecodeString(string(base64Content))
    if err != nil {
        return 2
    }
    // fmt.Println(rawContent)
    //     For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    // The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    for currentKeySizeGuess := 1; currentKeySizeGuess < 40; currentKeySizeGuess++ {
        innerCopy := make([]byte, len(rawContent))
        copy(innerCopy, rawContent)
        buff := bytes.NewBuffer(innerCopy)
        firstKeySizeWorthOfBytes := make([]byte, currentKeySizeGuess)
        secondKeySizeWorthOfBytes := make([]byte, currentKeySizeGuess)
        _, err := buff.Read(firstKeySizeWorthOfBytes)
        if err != nil {
            return 3
        }
        hammingDistance := HammingDistance(firstKeySizeWorthOfBytes, secondKeySizeWorthOfBytes)
        // fmt.Printf("Current: %v %v\n", hammingDistance, currentKeySizeGuess)
        // Need to support floats
        if hammingDistance != 0 {
            hammingDistance /= currentKeySizeGuess
        }
        if hammingDistance < bestHammingDistance {
            // fmt.Printf("New best: %v %v\n", hammingDistance, currentKeySizeGuess)
            bestHammingDistance = hammingDistance
            bestGuessKeySize = currentKeySizeGuess
        }
    }
    // Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    var keySizedBlocks [][]byte
    keySizedBlock := make([]byte, bestGuessKeySize)
    buffTwo := bytes.NewBuffer(rawContent)
    for {
        innerCopy := make([]byte, bestGuessKeySize)
        read, err := buffTwo.Read(keySizedBlock)
        if read == 0 {
            break
        }
        copy(innerCopy, keySizedBlock)
        keySizedBlocks = append(keySizedBlocks, innerCopy)
        if err != nil {
            break
        }
    }
    fmt.Println(keySizedBlocks)
    // Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    var transposedKeySizedBlocks [][]byte
    tranposedKeySizedBlock := make([]byte, bestGuessKeySize)
    for i := 0; i < bestGuessKeySize; i++ {
        for _, block := range keySizedBlocks {
            tranposedKeySizedBlock[i] = block[i]
        }
        transposedKeySizedBlocks = append(transposedKeySizedBlocks, tranposedKeySizedBlock)
    }
    fmt.Println(transposedKeySizedBlocks)
    // Solve each block as if it was single-character XOR.
    var key []byte
    for _, block := range transposedKeySizedBlocks {
        _, cipherKey, err := BreakSingleXORCipher(hex.EncodeToString(block))
        if err != nil {
            return 4
        }
        key = append(key, []byte(cipherKey)...)
    }
    fmt.Println(key)
    // For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
    return bestGuessKeySize
}

/*
   TODO: strip newlines
*/
