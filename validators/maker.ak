use aiken/crypto.{Blake2b_256, Hash, blake2b_256}
use cardano/address.{PaymentCredential}
use cardano/assets.{Lovelace}
use cardano/transaction.{OutputReference, Transaction}
use finite_interval.{expect_finite_interval}
use tagged_values.{ExpectedPayment, tagged_values_out_match}

pub type MakerDatum {
  beneficiary_payment: ExpectedPayment,
  resolver: PaymentCredential,
  deposit_amount: Lovelace,
  secret_hash: Hash<Blake2b_256, ByteArray>,
  //All variables below correspond to the last block of the named period, inclusive
  finality_lock: Int,
  resolver_unlock: Int,
  public_unlock: Int,
  resolver_cancellation: Int,
}

pub type Redeemer {
  secret: ByteArray,
  resolver: PaymentCredential,
}

validator make_escrow {
  spend(
    datum: Option<MakerDatum>,
    redeemer: Redeemer,
    ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(MakerDatum {
      beneficiary_payment,
      resolver,
      deposit_amount,
      secret_hash,
      finality_lock,
      resolver_unlock,
      public_unlock,
      resolver_cancellation,
    }) = datum

    let (low, high) = expect_finite_interval(tx.validity_range)

    if finality_lock < low && high <= resolver_unlock {
      //Here the selected resolver wants to proceed using the secret to get the deposit back.
      and {
        blake2b_256(redeemer.secret) == secret_hash,
        tagged_values_out_match(
          tx.outputs,
          beneficiary_payment,
          resolver,
          deposit_amount,
          ref,
        ),
      }
    } else if resolver_unlock < low && high <= public_unlock {
      //Here any resolver wants to proceed using the secret to get the deposit.
      and {
        blake2b_256(redeemer.secret) == secret_hash,
        tagged_values_out_match(
          tx.outputs,
          beneficiary_payment,
          redeemer.resolver,
          deposit_amount,
          ref,
        ),
      }
    } else if public_unlock < low && high < resolver_cancellation {
      //Here the resolver wants to cancel to get the deposit back.
      tagged_values_out_match(
        tx.outputs,
        beneficiary_payment,
        resolver,
        deposit_amount,
        ref,
      )
    } else if resolver_cancellation < low {
      //Here any resolver wants to cancel to get the deposit.
      tagged_values_out_match(
        tx.outputs,
        beneficiary_payment,
        redeemer.resolver,
        deposit_amount,
        ref,
      )
    } else {
      False
    }
  }

  else(_) {
    fail
  }
}
