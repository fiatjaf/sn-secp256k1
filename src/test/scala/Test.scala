import scala.scalanative.unsigned._
import utest._

import secp256k1.Secp256k1._

object Secp256k1Test extends TestSuite {
  val tests = Tests {
    test("loading pubkey") {
      val pkstring =
        "02c16cca44562b590dd279c942200bdccfd4f990c3a69fad620c10ef2f8228eaff"
      val pk = secp256k1.loadPublicKey(pkstring)
      assert(pk.isRight)
      pk.toOption.get.toHex ==> pkstring
    }

    test("loading private key") {
      val skstring =
        "c16cca44562b590dd279c942200bdccfd4f990c3a69fad620c10ef2f8228eaff"
      val sk = secp256k1.loadPrivateKey(skstring)
      assert(sk.isRight)
      sk.toOption.get.toHex ==> skstring
    }

    test("creating private keys") {
      val sk1 = secp256k1.createPrivateKey()
      val sk2 = secp256k1.createPrivateKey()
      val sk3 = secp256k1.createPrivateKey()
      val sk4 = secp256k1.createPrivateKey()

      sk1.value.size ==> 32
      sk2.value.size ==> 32
      sk3.value.size ==> 32
      sk4.value.size ==> 32

      assert(
        sk1.toHex != sk2.toHex,
        sk1.toHex != sk3.toHex,
        sk1.toHex != sk4.toHex,
        sk2.toHex != sk3.toHex,
        sk2.toHex != sk4.toHex,
        sk3.toHex != sk4.toHex
      )

      test("creating public keys") {
        val pk1 = sk1.publicKey()
        val pk2 = sk2.publicKey()
        val pk3 = sk3.publicKey()
        val pk4 = sk4.publicKey()

        pk1.value.size ==> 33
        pk2.value.size ==> 33
        pk3.value.size ==> 33
        pk4.value.size ==> 33

        assert(
          pk1.toHex != pk2.toHex,
          pk1.toHex != pk3.toHex,
          pk1.toHex != pk4.toHex,
          pk2.toHex != pk3.toHex,
          pk2.toHex != pk4.toHex,
          pk3.toHex != pk4.toHex,
          pk1.toHex != sk2.toHex,
          pk1.toHex != sk3.toHex,
          pk1.toHex != sk4.toHex,
          pk2.toHex != sk3.toHex,
          pk2.toHex != sk4.toHex,
          pk3.toHex != sk4.toHex
        )

        test("signing") {
          val sighash_a =
            "449e3caa7d12ada1521a5d251a3dde396fc9373d478f76e0fa5204cce2e85380"
          val sighash_b =
            "d396da2125adea97d008f109af685295cfcb2ac18a171768f3d2fbfcbb08313a"

          val sig1 = sk1.sign(sighash_a)
          assert(sig1.isRight)
          sig1.toOption.get.size ==> 64

          val sig2 = sk2.sign(sighash_a)
          assert(sig2.isRight)
          sig2.toOption.get.size ==> 64

          assert(sig1.toOption.get != sig2.toOption.get)

          val sig2again = sk2.sign(sighash_a)
          sig2.toOption.get ==> sig2again.toOption.get

          val sig3_a = sk3.sign(sighash_a)
          assert(sig3_a.isRight)
          sig3_a.toOption.get.size ==> 64

          val sig3_b = sk3.sign(sighash_b)
          assert(sig3_b.isRight)
          sig3_b.toOption.get.size ==> 64

          test("verifying") {
            pk1.verify(sighash_a, sig1.toOption.get) ==> Right(true)
            pk1.verify(sighash_a, sig2.toOption.get) ==> Right(false)
            pk2.verify(sighash_a, sig2.toOption.get) ==> Right(true)
            pk2.verify(sighash_b, sig2.toOption.get) ==> Right(false)
            pk3.verify(sighash_a, sig3_a.toOption.get) ==> Right(true)
            pk3.verify(sighash_a, sig3_b.toOption.get) ==> Right(false)
            pk3.verify(sighash_b, sig3_a.toOption.get) ==> Right(false)
            pk3.verify(sighash_b, sig3_b.toOption.get) ==> Right(true)
            pk3.verify(sighash_a, sig1.toOption.get) ==> Right(false)
          }
        }
      }
    }
  }
}
