package black

import (
    "testing"
)

func TestConvertHexToBase64(t *testing.T) {
    input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    output, err := ConvertHexToBase64(input)
    if err != nil {
        t.Errorf("Error %s running ConvertHexToBase64 with %s\n", err, input)
    }
    if output != expected {
        t.Errorf("Got: %s Expected: %s\n", output, expected)
    }
}

func TestFixedXOR(t *testing.T) {
    input := []string{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"}
    expected := "746865206b696420646f6e277420706c6179"
    output, err := FixedXOR(input[0], input[1])
    if err != nil {
        t.Errorf("Error %s running FixedXOR with %s\n", err, input)
    }
    if output != expected {
        t.Errorf("Got: %s Expected: %s\n", output, expected)
    }
}

func TestBreakSingleXORCipher(t *testing.T) {
    input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    expectedCipherKey := "X"
    expectedDecoded := "Cooking MC's like a pound of bacon"
    outputDecoded, outputCipherKey, err := BreakSingleXORCipher(input)
    if err != nil {
        t.Errorf("Error %s running BreakSingleXORCipher with %s \n", err, input)
    }
    if (outputCipherKey != expectedCipherKey) || (outputDecoded != expectedDecoded) {
        t.Errorf("Got: %s %s \nExpected: %s %s\n", outputCipherKey, outputDecoded, expectedCipherKey, expectedDecoded)
    }
}

func TestDetectSingleXOR(t *testing.T) {
    t.SkipNow()
    input := "samples/4.txt"
    expectedCipherKey := "5"
    expectedDecoded := "Now that the party is jumping\n"
    singleXorGuesses := DetectSingleXOR(input)
    var detected bool
    for _, guess := range singleXorGuesses {
        if guess.Decoded == expectedDecoded && guess.CipherKey == expectedCipherKey {
            detected = true
            break
        }
    }
    if !detected {
        t.Errorf("Failed to detect value: %s\n XORed with %s in %s\n", expectedDecoded, expectedCipherKey, input)
    }
}

func TestRepeatingKeyXOR(t *testing.T) {
    input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    inputKey := "ICE"
    expectedOutput := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    output := RepeatingKeyXOR(input, inputKey)
    if output != expectedOutput {
        t.Errorf("\nExpected: %s \nGot:      %s\n", expectedOutput, output)
    }
}

func TestBreakingRepeatingKeyXOR(t *testing.T) {

}
