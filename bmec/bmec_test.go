package bmec_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/monetas/bmd/bmec"
)

// TestAddJacobian tests addition of points projected in Jacobian coordinates.
func TestAddJacobian(t *testing.T) {
	tests := []struct {
		x1, y1, z1 string // Coordinates (in hex) of first point to add
		x2, y2, z2 string // Coordinates (in hex) of second point to add
		x3, y3, z3 string // Coordinates (in hex) of expected point
	}{
		// Addition with a point at infinity (left hand side).
		// ∞ + P = P
		{
			"0",
			"0",
			"0",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
		},
		// Addition with a point at infinity (right hand side).
		// P + ∞ = P
		{
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
			"0",
			"0",
			"0",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
		},

		// Addition with z1=z2=1 different x values.
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
			"0cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a6",
			"e205f79361bbe0346b037b4010985dbf4f9e1e955e7d0d14aca876bfa79aad87",
			"44a5646b446e3877a648d6d381370d9ef55a83b666ebce9df1b1d7d65b817b2f",
		},
		// Addition with z1=z2=1 same x opposite y.
		// P(x, y, z) + P(x, -y, z) = infinity
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
			"1",
			"0",
			"0",
			"0",
		},
		// Addition with z1=z2=1 same point.
		// P(x, y, z) + P(x, y, z) = 2P
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
			"b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
			"16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
		},

		// Addition with z1=z2 (!=1) different x values.
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"5d2fe112c21891d440f65a98473cb626111f8a234d2cd82f22172e369f002147",
			"98e3386a0a622a35c4561ffb32308d8e1c6758e10ebb1b4ebd3d04b4eb0ecbe8",
			"2",
			"cfbc7da1e569b334460788faae0286e68b3af7379d5504efc25e4dba16e46a60",
			"817de4d86ef80d1ac0ded00426176fd3e787a5579f43452b2a1db021e6ac3778",
			"129591ad11b8e1de99235b4e04dc367bd56a0ed99baf3a77c6c75f5a6e05f08d",
		},
		// Addition with z1=z2 (!=1) same x opposite y.
		// P(x, y, z) + P(x, -y, z) = infinity
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"a470ab21467813b6e0496d2c2b70c11446bab4fcbc9a52b7f225f30e869aea9f",
			"2",
			"0",
			"0",
			"0",
		},
		// Addition with z1=z2 (!=1) same point.
		// P(x, y, z) + P(x, y, z) = 2P
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
			"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
			"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
		},

		// Addition with z1!=z2 and z2=1 different x values.
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"1",
			"3ef1f68795a6ccd1181e23eab80a1b9a2cebdcde755413bf097936eb5b91b4f3",
			"0bef26c377c068d606f6802130bb7e9f3c3d2abcfa1a295950ed81133561cb04",
			"252b235a2371c3bd3246b69c09b86cf7aad41db3375e74ef8d8ebeb4dc0be11a",
		},
		// Addition with z1!=z2 and z2=1 same x opposite y.
		// P(x, y, z) + P(x, -y, z) = infinity
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
			"1",
			"0",
			"0",
			"0",
		},
		// Addition with z1!=z2 and z2=1 same point.
		// P(x, y, z) + P(x, y, z) = 2P
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
			"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
			"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
		},

		// Addition with z1!=z2 and z2!=1 different x values.
		// P(x, y, z) + P(x, y, z) = 2P
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"91abba6a34b7481d922a4bd6a04899d5a686f6cf6da4e66a0cb427fb25c04bd4",
			"03fede65e30b4e7576a2abefc963ddbf9fdccbf791b77c29beadefe49951f7d1",
			"3",
			"3f07081927fd3f6dadd4476614c89a09eba7f57c1c6c3b01fa2d64eac1eef31e",
			"949166e04ebc7fd95a9d77e5dfd88d1492ecffd189792e3944eb2b765e09e031",
			"eb8cba81bcffa4f44d75427506737e1f045f21e6d6f65543ee0e1d163540c931",
		}, // Addition with z1!=z2 and z2!=1 same x opposite y.
		// P(x, y, z) + P(x, -y, z) = infinity
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
			"cafc41904dd5428934f7d075129c8ba46eb622d4fc88d72cd1401452664add18",
			"3",
			"0",
			"0",
			"0",
		},
		// Addition with z1!=z2 and z2!=1 same point.
		// P(x, y, z) + P(x, y, z) = 2P
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"dcc3768780c74a0325e2851edad0dc8a566fa61a9e7fc4a34d13dcb509f99bc7",
			"3503be6fb22abd76cb082f8aed63745b9149dd2b037728d32ebfebac99b51f17",
			"3",
			"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
			"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
			"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Convert hex to field values.
		x1 := bmec.NewFieldVal().SetHex(test.x1)
		y1 := bmec.NewFieldVal().SetHex(test.y1)
		z1 := bmec.NewFieldVal().SetHex(test.z1)
		x2 := bmec.NewFieldVal().SetHex(test.x2)
		y2 := bmec.NewFieldVal().SetHex(test.y2)
		z2 := bmec.NewFieldVal().SetHex(test.z2)
		x3 := bmec.NewFieldVal().SetHex(test.x3)
		y3 := bmec.NewFieldVal().SetHex(test.y3)
		z3 := bmec.NewFieldVal().SetHex(test.z3)

		// Ensure the test data is using points that are actually on
		// the curve (or the point at infinity).
		if !z1.IsZero() && !bmec.S256().TstIsJacobianOnCurve(x1, y1, z1) {
			t.Errorf("#%d first point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !z2.IsZero() && !bmec.S256().TstIsJacobianOnCurve(x2, y2, z2) {
			t.Errorf("#%d second point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !z3.IsZero() && !bmec.S256().TstIsJacobianOnCurve(x3, y3, z3) {
			t.Errorf("#%d expected point is not on the curve -- "+
				"invalid test data", i)
			continue
		}

		// Add the two points.
		rx, ry, rz := bmec.NewFieldVal(), bmec.NewFieldVal(), bmec.NewFieldVal()
		bmec.S256().TstAddJacobian(x1, y1, z1, x2, y2, z2, rx, ry, rz)

		// Ensure result matches expected.
		if !rx.Equals(x3) || !ry.Equals(y3) || !rz.Equals(z3) {
			t.Errorf("#%d wrong result\ngot: (%v, %v, %v)\n"+
				"want: (%v, %v, %v)", i, rx, ry, rz, x3, y3, z3)
			continue
		}
	}
}

// TestAddAffine tests addition of points in affine coordinates.
func TestAddAffine(t *testing.T) {
	tests := []struct {
		x1, y1 string // Coordinates (in hex) of first point to add
		x2, y2 string // Coordinates (in hex) of second point to add
		x3, y3 string // Coordinates (in hex) of expected point
	}{
		// Addition with a point at infinity (left hand side).
		// ∞ + P = P
		{
			"0",
			"0",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
		},
		// Addition with a point at infinity (right hand side).
		// P + ∞ = P
		{
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"0",
			"0",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
		},

		// Addition with different x values.
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575",
			"131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d",
			"fd5b88c21d3143518d522cd2796f3d726793c88b3e05636bc829448e053fed69",
			"21cf4f6a5be5ff6380234c50424a970b1f7e718f5eb58f68198c108d642a137f",
		},
		// Addition with same x opposite y.
		// P(x, y) + P(x, -y) = infinity
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"f48e156428cf0276dc092da5856e182288d7569f97934a56fe44be60f0d359fd",
			"0",
			"0",
		},
		// Addition with same point.
		// P(x, y) + P(x, y) = 2P
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"59477d88ae64a104dbb8d31ec4ce2d91b2fe50fa628fb6a064e22582196b365b",
			"938dc8c0f13d1e75c987cb1a220501bd614b0d3dd9eb5c639847e1240216e3b6",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Convert hex to field values.
		x1, y1 := fromHex(test.x1), fromHex(test.y1)
		x2, y2 := fromHex(test.x2), fromHex(test.y2)
		x3, y3 := fromHex(test.x3), fromHex(test.y3)

		// Ensure the test data is using points that are actually on
		// the curve (or the point at infinity).
		if !(x1.Sign() == 0 && y1.Sign() == 0) && !bmec.S256().IsOnCurve(x1, y1) {
			t.Errorf("#%d first point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !(x2.Sign() == 0 && y2.Sign() == 0) && !bmec.S256().IsOnCurve(x2, y2) {
			t.Errorf("#%d second point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !(x3.Sign() == 0 && y3.Sign() == 0) && !bmec.S256().IsOnCurve(x3, y3) {
			t.Errorf("#%d expected point is not on the curve -- "+
				"invalid test data", i)
			continue
		}

		// Add the two points.
		rx, ry := bmec.S256().Add(x1, y1, x2, y2)

		// Ensure result matches expected.
		if rx.Cmp(x3) != 00 || ry.Cmp(y3) != 0 {
			t.Errorf("#%d wrong result\ngot: (%x, %x)\n"+
				"want: (%x, %x)", i, rx, ry, x3, y3)
			continue
		}
	}
}

// TestDoubleJacobian tests doubling of points projected in Jacobian
// coordinates.
func TestDoubleJacobian(t *testing.T) {
	tests := []struct {
		x1, y1, z1 string // Coordinates (in hex) of point to double
		x3, y3, z3 string // Coordinates (in hex) of expected point
	}{
		// Doubling a point at infinity is still infinity.
		{
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
		},
		// Doubling with z1=1.
		{
			"34f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6",
			"0b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232",
			"1",
			"ec9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee64f87c50c27",
			"b082b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd0755c8f2a",
			"16e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c1e594464",
		},
		// Doubling with z1!=1.
		{
			"d3e5183c393c20e4f464acf144ce9ae8266a82b67f553af33eb37e88e7fd2718",
			"5b8f54deb987ec491fb692d3d48f3eebb9454b034365ad480dda0cf079651190",
			"2",
			"9f153b13ee7bd915882859635ea9730bf0dc7611b2c7b0e37ee65073c50fabac",
			"2b53702c466dcf6e984a35671756c506c67c2fcb8adb408c44dd125dc91cb988",
			"6e3d537ae61fb1247eda4b4f523cfbaee5152c0d0d96b520376833c2e5944a11",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Convert hex to field values.
		x1 := bmec.NewFieldVal().SetHex(test.x1)
		y1 := bmec.NewFieldVal().SetHex(test.y1)
		z1 := bmec.NewFieldVal().SetHex(test.z1)
		x3 := bmec.NewFieldVal().SetHex(test.x3)
		y3 := bmec.NewFieldVal().SetHex(test.y3)
		z3 := bmec.NewFieldVal().SetHex(test.z3)

		// Ensure the test data is using points that are actually on
		// the curve (or the point at infinity).
		if !z1.IsZero() && !bmec.S256().TstIsJacobianOnCurve(x1, y1, z1) {
			t.Errorf("#%d first point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !z3.IsZero() && !bmec.S256().TstIsJacobianOnCurve(x3, y3, z3) {
			t.Errorf("#%d expected point is not on the curve -- "+
				"invalid test data", i)
			continue
		}

		// Double the point.
		rx, ry, rz := bmec.NewFieldVal(), bmec.NewFieldVal(), bmec.NewFieldVal()
		bmec.S256().TstDoubleJacobian(x1, y1, z1, rx, ry, rz)

		// Ensure result matches expected.
		if !rx.Equals(x3) || !ry.Equals(y3) || !rz.Equals(z3) {
			t.Errorf("#%d wrong result\ngot: (%v, %v, %v)\n"+
				"want: (%v, %v, %v)", i, rx, ry, rz, x3, y3, z3)
			continue
		}
	}
}

// TestDoubleAffine tests doubling of points in affine coordinates.
func TestDoubleAffine(t *testing.T) {
	tests := []struct {
		x1, y1 string // Coordinates (in hex) of point to double
		x3, y3 string // Coordinates (in hex) of expected point
	}{
		// Doubling a point at infinity is still infinity.
		// 2*∞ = ∞ (point at infinity)

		{
			"0",
			"0",
			"0",
			"0",
		},

		// Random points.
		{
			"e41387ffd8baaeeb43c2faa44e141b19790e8ac1f7ff43d480dc132230536f86",
			"1b88191d430f559896149c86cbcb703193105e3cf3213c0c3556399836a2b899",
			"88da47a089d333371bd798c548ef7caae76e737c1980b452d367b3cfe3082c19",
			"3b6f659b09a362821dfcfefdbfbc2e59b935ba081b6c249eb147b3c2100b1bc1",
		},
		{
			"b3589b5d984f03ef7c80aeae444f919374799edf18d375cab10489a3009cff0c",
			"c26cf343875b3630e15bccc61202815b5d8f1fd11308934a584a5babe69db36a",
			"e193860172998751e527bb12563855602a227fc1f612523394da53b746bb2fb1",
			"2bfcf13d2f5ab8bb5c611fab5ebbed3dc2f057062b39a335224c22f090c04789",
		},
		{
			"2b31a40fbebe3440d43ac28dba23eee71c62762c3fe3dbd88b4ab82dc6a82340",
			"9ba7deb02f5c010e217607fd49d58db78ec273371ea828b49891ce2fd74959a1",
			"2c8d5ef0d343b1a1a48aa336078eadda8481cb048d9305dc4fdf7ee5f65973a2",
			"bb4914ac729e26d3cd8f8dc8f702f3f4bb7e0e9c5ae43335f6e94c2de6c3dc95",
		},
		{
			"61c64b760b51981fab54716d5078ab7dffc93730b1d1823477e27c51f6904c7a",
			"ef6eb16ea1a36af69d7f66524c75a3a5e84c13be8fbc2e811e0563c5405e49bd",
			"5f0dcdd2595f5ad83318a0f9da481039e36f135005420393e72dfca985b482f4",
			"a01c849b0837065c1cb481b0932c441f49d1cab1b4b9f355c35173d93f110ae0",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Convert hex to field values.
		x1, y1 := fromHex(test.x1), fromHex(test.y1)
		x3, y3 := fromHex(test.x3), fromHex(test.y3)

		// Ensure the test data is using points that are actually on
		// the curve (or the point at infinity).
		if !(x1.Sign() == 0 && y1.Sign() == 0) && !bmec.S256().IsOnCurve(x1, y1) {
			t.Errorf("#%d first point is not on the curve -- "+
				"invalid test data", i)
			continue
		}
		if !(x3.Sign() == 0 && y3.Sign() == 0) && !bmec.S256().IsOnCurve(x3, y3) {
			t.Errorf("#%d expected point is not on the curve -- "+
				"invalid test data", i)
			continue
		}

		// Double the point.
		rx, ry := bmec.S256().Double(x1, y1)

		// Ensure result matches expected.
		if rx.Cmp(x3) != 00 || ry.Cmp(y3) != 0 {
			t.Errorf("#%d wrong result\ngot: (%x, %x)\n"+
				"want: (%x, %x)", i, rx, ry, x3, y3)
			continue
		}
	}
}

func TestOnCurve(t *testing.T) {
	s256 := bmec.S256()
	if !s256.IsOnCurve(s256.Params().Gx, s256.Params().Gy) {
		t.Errorf("FAIL S256")
	}
}

type baseMultTest struct {
	k    string
	x, y string
}

//TODO: add more test vectors
var s256BaseMultTests = []baseMultTest{
	{
		"AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
		"34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
		"B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
	},
	{
		"7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
		"D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
		"131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
	},
	{
		"6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
		"E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
		"C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
	},
	{
		"376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
		"14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
		"297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
	},
	{
		"1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
		"F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
		"F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
	},
}

//TODO: test different curves as well?
func TestBaseMult(t *testing.T) {
	s256 := bmec.S256()
	for i, e := range s256BaseMultTests {
		k, ok := new(big.Int).SetString(e.k, 16)
		if !ok {
			t.Errorf("%d: bad value for k: %s", i, e.k)
		}
		x, y := s256.ScalarBaseMult(k.Bytes())
		if fmt.Sprintf("%X", x) != e.x || fmt.Sprintf("%X", y) != e.y {
			t.Errorf("%d: bad output for k=%s: got (%X, %X), want (%s, %s)", i,
				e.k, x, y, e.x, e.y)
		}
		if testing.Short() && i > 5 {
			break
		}
	}
}

func TestBaseMultVerify(t *testing.T) {
	s256 := bmec.S256()
	for bytes := 1; bytes < 40; bytes++ {
		for i := 0; i < 30; i++ {
			data := make([]byte, bytes)
			_, err := rand.Read(data)
			if err != nil {
				t.Errorf("failed to read random data for %d", i)
				continue
			}
			x, y := s256.ScalarBaseMult(data)
			xWant, yWant := s256.ScalarMult(s256.Gx, s256.Gy, data)
			if x.Cmp(xWant) != 0 || y.Cmp(yWant) != 0 {
				t.Errorf("%d: bad output for %X: got (%X, %X), want (%X, %X)",
					i, data, x, y, xWant, yWant)
			}
			if testing.Short() && i > 2 {
				break
			}
		}
	}
}

func TestScalarMult(t *testing.T) {
	// Strategy for this test:
	// Get a random exponent from the generator point at first
	// This creates a new point which is used in the next iteration
	// Use another random exponent on the new point.
	// We use BaseMult to verify by multiplying the previous exponent
	// and the new random exponent together (mod N)
	s256 := bmec.S256()
	x, y := s256.Gx, s256.Gy
	exponent := big.NewInt(1)
	for i := 0; i < 1024; i++ {
		data := make([]byte, 32)
		_, err := rand.Read(data)
		if err != nil {
			t.Fatalf("failed to read random data at %d", i)
			break
		}
		x, y = s256.ScalarMult(x, y, data)
		exponent.Mul(exponent, new(big.Int).SetBytes(data))
		xWant, yWant := s256.ScalarBaseMult(exponent.Bytes())
		if x.Cmp(xWant) != 0 || y.Cmp(yWant) != 0 {
			t.Fatalf("%d: bad output for %X: got (%X, %X), want (%X, %X)", i,
				data, x, y, xWant, yWant)
			break
		}
	}
}

// Test this curve's usage with the ecdsa package.

func testKeyGeneration(t *testing.T, c *bmec.KoblitzCurve, tag string) {
	priv, err := bmec.NewPrivateKey(c)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("%s: public key invalid: %s", tag, err)
	}
}

func TestKeyGeneration(t *testing.T) {
	testKeyGeneration(t, bmec.S256(), "S256")
}

func testSignAndVerify(t *testing.T, c *bmec.KoblitzCurve, tag string) {
	priv, _ := bmec.NewPrivateKey(c)
	pub := priv.PubKey()

	hashed := []byte("testing")
	sig, err := priv.Sign(hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !sig.Verify(hashed, pub) {
		t.Errorf("%s: Verify failed", tag)
	}

	hashed[0] ^= 0xff
	if sig.Verify(hashed, pub) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func TestSignAndVerify(t *testing.T) {
	testSignAndVerify(t, bmec.S256(), "S256")
}

func TestNAF(t *testing.T) {
	negOne := big.NewInt(-1)
	one := big.NewInt(1)
	two := big.NewInt(2)
	for i := 0; i < 1024; i++ {
		data := make([]byte, 32)
		_, err := rand.Read(data)
		if err != nil {
			t.Fatalf("failed to read random data at %d", i)
			break
		}
		nafPos, nafNeg := bmec.NAF(data)
		want := new(big.Int).SetBytes(data)
		got := big.NewInt(0)
		// Check that the NAF representation comes up with the right number
		for i := 0; i < len(nafPos); i++ {
			bytePos := nafPos[i]
			byteNeg := nafNeg[i]
			for j := 7; j >= 0; j-- {
				got.Mul(got, two)
				if bytePos&0x80 == 0x80 {
					got.Add(got, one)
				} else if byteNeg&0x80 == 0x80 {
					got.Add(got, negOne)
				}
				bytePos <<= 1
				byteNeg <<= 1
			}
		}
		if got.Cmp(want) != 0 {
			t.Errorf("%d: Failed NAF got %X want %X", i, got, want)
		}
	}
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}
