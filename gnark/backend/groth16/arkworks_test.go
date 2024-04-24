package groth16

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tests adapted from https://github.com/esuwu/groth16-verifier-bls12381
func TestVerifyArkworksProof(t *testing.T) {
	for _, test := range []struct {
		vk     string
		proof  string
		inputs string
		ok     bool
	}{
		{"GBn2MvqNck41HSUIHqMczzeZkawlyQZm4HED//sELtkcdjUc1aJAQbQOJtIxpQh+AVTOB9GnMvI83biSUy7C7Bf38u9DkIjowyI3ZReIDv/FrXQ1jnTSeb0jYJHyoDMwBx82qZbHGolJn/6Zqn0/lN7N0sqLBw27Rn5C0lqtkYr27JTWGwuJnI9ySytUnZn8FiOg5Rts++oiDnDn2lgDyK0RRKZ/mJNKa/KIHsZAdnj9UnEUZq1gjWdsYDGaKZgkCu0z9pf/JeBlCUU0ZCUg4IYqvfiYaR98+I9XvcrUT47SG3YIuZtK62E2cpzJcvDeDh+Ct0TbJFm6PdNyxl19cZIjJvFI4Efi9AF9m81OdE91ISmJb0ZZzMwf9kuSF9oIFnUNhEVZavjWeUh8cmeulzSurFhKzhkdIlaAoY7P+Ouubdal/WjkQUsWERZJBO4SA2PCtJ8zqHPWz8JiSbZjJ6DeA+ZzuBOfeYCei2QVhs3plD+gcu5e1wHIGz/UJsIgBYeX1RcKOZ3ppkDH+Zp0YsGtifrwUAURzOSE4OFi7AEEHChTXsx+6PNQWrholqAQB+bnGDuY+fTRHVNUhJZWfjwCoFs5SA2rXXJV1yrL2ArmxNqrDx0M1nbBZf5Zodo/DTrIMvJQivbwGHKtqH6mbS+1sJnTTFusgedILJVidt/CNMjSr1/SOUtUQNBwiiyfEkpTwHVelZXPn4ra3l3u/LildKZ969O3TQjEnCPdwUzW1Itl3OUAyKXTMOdg/oW7DDF00ZX1MIp2uQJq02n0EmA0bXpj6gVE9g29+gZChumInBHOCpCuX0WHdtT10zKEDjNCO+2k3gW+2JkA3ofJaiOw2c5O6L3gwk4HZL74tkEjFFrFcXwYP0S2DPAhcvuYAgAAAAAAAAAQ33YNDy1n/f9p0O06BlPdiAjfPEB+pNDif4YSw/u3SMtDctM8rFEu5e9O4Wg8P+UXuaeEY4tHnmcR24kZIFQz6Kb1oGmAoy5+nzvopLE8EQjORO08C0ySeogOw6eU2tcW7IDWsQULv8IJ9ydniszoeIwFR1dx2v/dRErYeGx6QBldhZhQ/i5yvjBU6fuM6AUMLMM7yDkTaVTDM8Y5B9GiivtkFzKhqZsfd8UJ2qzxisg5nVS1+PqfilZ0jA9B3YU=", "DM+KjDng6p+qO2M7/uw+ES+N+wgXeG/WjuAzb3ltP4+UYGqMjxxSfVEtm2kI8lfeAitCtvzAGLJHu/hGnW+9Efmr+8OWFc+bhg2VxbfoBxU1pisUJFfbKzdZgOjdMSPdDmlMjptygC9Q5GiAacW5laWpAjcrsSzbHkk/nnnFtFBy1sSQ+Kuqrlc9IabSb8JsErJ9JulK5/kb1z4YcCB6MOiW+SOSFZuVYIE8zv1C0mDrBGQTp4K1fhkjP1Pwr6LsDawdZX6TDYznHHDErAT0g+L277qYukZQzDqyXaKGUTdt8MJjmAaDf11VMoJeV+hCBMb3vT4NijzZxIGcy0iV1ROR7EXssXBfEfTfsNAUTR+yIVcjudM+l9wZ/OzwbTi6AdD1sH8SPh30KncZT3Tlqmm/WSZ+ToCSsie9xrfX4fCZePzjFMmt5bP2s6KsN+0EEzryX5r1E01OiyJPQSNcdq12JQ8Sp0Kp8cz4YwhhvqrDrkCtKB62ZHna+WQHmwUZ", "AQAAAAAAAABvP35ar9waPuSngei09jMmzuvh5vqc5qI/lADfug14UQ==", true},
	} {
		// decode verifying key
		vk := NewVerifyingKey(ecc.BLS12_381)

		vkBytes, err := base64.StdEncoding.DecodeString(test.vk)
		require.NoError(t, err)

		_, err = vk.ReadFrom(bytes.NewReader(vkBytes))
		require.NoError(t, err)

		// decode proof
		fmt.Printf("decoding proof\n")
		proofBytes, err := base64.StdEncoding.DecodeString(test.proof)
		require.NoError(t, err)

		// pad with 0 bytes to account for commitment stuff
		proofBytes = append(proofBytes, make([]byte, bls12381.SizeOfG1AffineUncompressed+4)...)

		proof := NewProof(ecc.BLS12_381)
		_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
		require.NoError(t, err)
		fmt.Printf("decoded proof\n")

		// decode inputs
		fmt.Printf("decoding inputs\n")
		inputsBytes, err := base64.StdEncoding.DecodeString(test.inputs)
		require.NoError(t, err)
		fmt.Printf("decoded inputs: %v\n", inputsBytes)

		// verify groth16 proof
		// we need to prepend the number of elements in the witness.
		// witness package expects [nbPublic nbSecret] followed by [n | elements];
		// note that n is redundant with nbPublic + nbSecret
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(inputsBytes)/(fr.Limbs*8)))
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(inputsBytes)/(fr.Limbs*8)))
		buf.Write(inputsBytes[8:])
		fmt.Printf("buf: %v\n", buf.Bytes())

		witness, err := witness.New(ecc.BLS12_381.ScalarField())
		require.NoError(t, err)

		err = witness.UnmarshalBinary(buf.Bytes())
		require.NoError(t, err)
		fmt.Printf("unmarshalled witness: %v\n", witness)

		err = Verify(proof, vk, witness)
		if test.ok {
			assert.NoError(t, err)
		}
	}
}
