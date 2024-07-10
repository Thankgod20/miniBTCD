package elliptical

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/Thankgod20/miniBTCD/trx"
	"golang.org/x/crypto/ripemd160"
)

// Elliptic Curve Parameters
var (
	a    = big.NewInt(0)
	b    = big.NewInt(7)
	p, _ = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	n, _ = new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)

	// Generator point
	Gx, _ = new(big.Int).SetString("55066263022277343669578718895168534326250603453777594175500187360389116729240", 10)
	Gy, _ = new(big.Int).SetString("32670510020758816978083085130507043184471273380659243275938904335757337482424", 10)
	G     = &Point{Gx, Gy}
)

// Point represents a point on the elliptic curve.
type Point struct {
	X, Y *big.Int
}
type Signature struct {
	R, S *big.Int
}

// ModularInverse calculates the modular inverse of a with respect to m.
func ModularInverse(a, m *big.Int) *big.Int {
	mOrig := new(big.Int).Set(m)
	a = new(big.Int).Mod(a, m)
	prevY, y := big.NewInt(0), big.NewInt(1)
	for a.Cmp(big.NewInt(1)) > 0 {
		q := new(big.Int).Div(m, a)
		y, prevY = new(big.Int).Sub(prevY, new(big.Int).Mul(q, y)), y
		a, m = new(big.Int).Mod(m, a), a
	}
	return new(big.Int).Mod(y, mOrig)
}

// Double doubles a point on the elliptic curve.
func Double(point *Point) *Point {
	// slope = (3*x^2 + a) / (2*y)
	numerator := new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(3), new(big.Int).Exp(point.X, big.NewInt(2), nil)),
		a,
	)
	denominator := new(big.Int).Mul(big.NewInt(2), point.Y)
	slope := new(big.Int).Mod(new(big.Int).Mul(numerator, ModularInverse(denominator, p)), p)

	// x = slope^2 - 2*x
	x := new(big.Int).Mod(
		new(big.Int).Sub(new(big.Int).Exp(slope, big.NewInt(2), nil), new(big.Int).Mul(big.NewInt(2), point.X)),
		p,
	)

	// y = slope * (x - x₁) - y₁
	y := new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(slope, new(big.Int).Sub(point.X, x)),
			point.Y,
		),
		p,
	)

	return &Point{x, y}
}

// Add adds two points on the elliptic curve.
func Add(point1, point2 *Point) *Point {
	// Double if both points are the same
	if point1 == point2 {
		return Double(point1)
	}

	// slope = (y1 - y2) / (x1 - x2)
	numerator := new(big.Int).Sub(point1.Y, point2.Y)
	denominator := new(big.Int).Sub(point1.X, point2.X)
	slope := new(big.Int).Mod(new(big.Int).Mul(numerator, ModularInverse(denominator, p)), p)

	// x = slope^2 - x1 - x2
	x := new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(new(big.Int).Exp(slope, big.NewInt(2), nil), point1.X),
			point2.X,
		),
		p,
	)

	// y = slope * (x1 - x) - y1
	y := new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(slope, new(big.Int).Sub(point1.X, x)),
			point1.Y, //y,
		),
		p,
	)

	return &Point{x, y}
}

// Multiply performs scalar multiplication k*point on the elliptic curve.
func Multiply(k *big.Int, point *Point) *Point {
	// Create a copy of the initial starting point (for use in addition later on)
	current := &Point{new(big.Int).Set(point.X), new(big.Int).Set(point.Y)}

	// Convert integer k to binary representation
	binary := k.Text(2)

	// Double and add algorithm for fast multiplication
	for i := 1; i < len(binary); i++ {
		// Double the current point
		current = Double(current)

		// If the current binary digit is '1', add the original point to the current point
		if binary[i] == '1' {
			current = Add(current, point)
		}
	}

	return current
}

// Sign signs a hash with the given private key and returns the signature (r, s).
func Sign(privateKey *big.Int, hash []byte, nonce *big.Int) (r, s *big.Int, err error) {
	// Generate random nonce if not provided
	if nonce == nil {
		for {
			nonceBytes := make([]byte, 32)
			_, err := rand.Read(nonceBytes)
			if err != nil {
				return nil, nil, err
			}
			nonce = new(big.Int).SetBytes(nonceBytes)
			if nonce.Cmp(n) < 0 { // Check if nonce < n
				break
			}
		}
	}

	// Calculate r = x coordinate of nonce * G mod n
	r = new(big.Int).Mod(Multiply(nonce, G).X, n)

	// Convert hash to big.Int
	hashInt := new(big.Int).SetBytes(hash)

	// Calculate s = nonce⁻¹ * (hash + private_key * r) mod n
	nonceInv := ModularInverse(nonce, n)
	tmp := new(big.Int).Mul(privateKey, r)
	tmp.Add(hashInt, tmp)
	s = new(big.Int).Mul(nonceInv, tmp)
	s.Mod(s, n)

	return r, s, nil
}

// Verify verifies a signature against a public key and hash.
func Verify(publicKey Point, signature Signature, hash []byte) bool {
	// Calculate point1 = multiply(inverse(signature.s, n) * hash)
	sInv := ModularInverse(signature.S, n)
	point1 := Multiply(new(big.Int).Mul(sInv, new(big.Int).SetBytes(hash)), G)

	// Calculate point2 = multiply(inverse(signature.s, n) * signature.r, publicKey)
	tmp := new(big.Int).Mul(sInv, signature.R)
	point2 := Multiply(tmp, &publicKey)

	// Add point1 and point2 together
	point3 := Add(point1, point2)

	// Check if x-coordinate of point3 matches signature.r
	return point3.X.Cmp(signature.R) == 0
}
func ComputeTransactionID(txBytes []byte) []byte {
	hash1 := sha256.Sum256(txBytes)
	hash2 := sha256.Sum256(hash1[:])
	txid := trx.ReverseBytes(hash2[:])
	return txid //hash2[:]
}
func DecompressPubKeyTx(compressed string) ([]byte, *big.Int, *big.Int) {
	//compressed := "0298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d"

	// Split compressed key into prefix and x-coordinate
	prefix := compressed[:2]
	xHex := compressed[2:]

	// Convert x-coordinate from hex string to integer
	x, _ := new(big.Int).SetString(xHex, 16)

	// Secp256k1 curve parameters
	pHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	p, _ := new(big.Int).SetString(pHex, 16)

	// Work out y values using the curve equation y^2 = x^3 + 7
	seven := big.NewInt(7)
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	xCubed.Add(xCubed, seven)
	ySq := new(big.Int).Mod(xCubed, p)

	// Secp256k1 is chosen in a special way so that the square root of y is y^((p+1)/4)
	exponent := new(big.Int).Add(p, big.NewInt(1))
	exponent.Div(exponent, big.NewInt(4))
	y := new(big.Int).Exp(ySq, exponent, p)

	// Use prefix to select the correct value for y
	if (prefix == "02" && y.Bit(0) != 0) || (prefix == "03" && y.Bit(0) == 0) {
		y.Sub(p, y)
	}

	// Construct the uncompressed public key
	xStr := fmt.Sprintf("%064x", x)
	yStr := fmt.Sprintf("%064x", y)
	uncompressed := "04" + xStr + yStr

	// Result
	fmt.Println("XX:", xStr)
	fmt.Println("YY:", yStr)
	fmt.Println(uncompressed)
	byteUncmp, err := hex.DecodeString(uncompressed)
	if err != nil {
		log.Println("failed to decompress public key")
	}
	Xx, err := hex.DecodeString(xStr)
	if err != nil {
		fmt.Println("Error converting hex string to big.Int")

	}
	Yy, err := hex.DecodeString(yStr)
	if err != nil {
		fmt.Println("Error converting hex string to big.Int")

	}
	X := new(big.Int).SetBytes(Xx)
	Y := new(big.Int).SetBytes(Yy)
	return byteUncmp, X, Y
}

// DecompressPubKey decompresses a compressed public key
func DecompressPubKey(pubKey []byte) ([]byte, error) {
	log.Printf("Decompressing Pubkey... %x", pubKey)
	if len(pubKey) != 33 || (pubKey[0] != 0x02 && pubKey[0] != 0x03) {
		return nil, errors.New("invalid compressed public key format")
	}
	//fmt.Println("pubKey[1:]", pubKey[1:])
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubKey[1:])
	y := decompressYCoordinate(curve, pubKey[0] == 0x03, x)
	//fmt.Println("X,Y", x, y)
	if y == nil {
		return nil, errors.New("failed to decompress public key")
	}

	decompressedPubKey := elliptic.Marshal(curve, x, y)
	return decompressedPubKey, nil
}

// decompressYCoordinate computes the y-coordinate from the x-coordinate for a given curve
func decompressYCoordinate(curve elliptic.Curve, isOdd bool, x *big.Int) *big.Int {
	// P-256 parameters
	p := curve.Params().P
	a := big.NewInt(-3)
	b := new(big.Int)
	b.SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

	// Calculate x^3 + ax + b (mod p)
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, p)
	result := new(big.Int).Add(xCubed, ax)
	result.Add(result, b)
	result.Mod(result, p)

	// Calculate the modular square root (y-coordinate)
	y := new(big.Int).ModSqrt(result, p)
	if y == nil {
		return nil //, fmt.Errorf("no valid y-coordinate for x = %s", x.Text(16))
	}
	if y.Bit(0) != 0 {
		if !isOdd {
			y = new(big.Int).Sub(curve.Params().P, y)
		}
	} else {
		if isOdd {
			y = new(big.Int).Sub(curve.Params().P, y)
		}
	}
	return y //, nil
}
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}
