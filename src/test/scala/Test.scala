import scala.scalanative.unsigned._
import utest._

import secp256k1.Secp256k1._

object Secp256k1Test extends TestSuite {
  val tests = Tests {
    test("loading pubkey compressed, output uncompressed") {
      val pkstring =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      val pk = secp256k1.loadPublicKey(pkstring)
      assert(pk.isRight)
      pk.toOption.get.toHex ==> "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

      bytearray2hex(
        pk.toOption.get
          .toUncompressed()
      ) ==> "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    }

    test("loading pubkey uncompressed, output compressed") {
      val pkstring =
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      val pk = secp256k1.loadPublicKey(pkstring)
      assert(pk.isRight)

      // it is stored in compressed form
      pk.toOption.get.toHex ==> "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

      bytearray2hex(
        pk.toOption.get
          .toCompressed()
      ) ==> "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
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

    test("xonly keys") {
      List(
        (
          "0000000000000000000000000000000000000000000000000000000000000003",
          "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        ),
        (
          "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
          "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
        ),
        (
          "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
          "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"
        ),
        (
          "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
          "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517"
        )
      ).foreach((sk, pk) =>
        secp256k1.loadPrivateKey(sk).toOption.get.publicKey().xonly.toHex ==> pk
      )
    }

    test("schnorr sign and verify good") {
      List(
        (
          "0000000000000000000000000000000000000000000000000000000000000003",
          "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ),
        (
          "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
          "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
          "0000000000000000000000000000000000000000000000000000000000000001",
          "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
          "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"
        ),
        (
          "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
          "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
          "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
          "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
          "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7"
        ),
        (
          "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
          "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3"
        )
      ).foreach { (sk, pk, aux, msg, sig) =>
        bytearray2hex(
          secp256k1
            .loadPrivateKey(sk)
            .toOption
            .get
            .signSchnorr(msg, aux)
            .toOption
            .get
        ) ==> sig
      }
    }

    test("schnorr verify bad") {
      List(
        (
          "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
          "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
          "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd"
        ),
        (
          "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
          "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
          "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051"
        )
      ).foreach { (pk, msg, sig) =>
        secp256k1
          .loadPublicKey(pk)
          .toOption
          .map(
            _.xonly
              .verifySchnorr(msg, sig)
          ) ==> Some(Right(false))
      }
    }
  }
}
