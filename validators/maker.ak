use aiken/collection/list
use aiken/crypto.{Blake2b_256, Hash, blake2b_256}
use cardano/address.{PaymentCredential}
use cardano/assets.{Lovelace, from_lovelace, merge, negate}
use cardano/transaction.{Output, OutputReference, Transaction}
use finite_interval.{expect_finite_interval}
use tagged_values.{ExpectedPayment, tagged_values_out_match}

pub type TakerDatum {
  beneficiary: PaymentCredential,
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
    datum: Option<TakerDatum>,
    redeemer: Redeemer,
    ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(TakerDatum {
      beneficiary,
      resolver,
      deposit_amount,
      secret_hash,
      finality_lock,
      resolver_unlock,
      public_unlock,
      resolver_cancellation,
    }) = datum
    let deposit_amount = from_lovelace(deposit_amount)

    let (low, high) = expect_finite_interval(tx.validity_range)

    expect Some(value_in) =
      list.find(tx.inputs, fn(input) { input.output_reference == ref })
    let value_in = value_in.output

    if finality_lock < low && high <= resolver_unlock {
      //Here the selected resolver wants to proceed using the secret to get the deposit back.
      and {
        blake2b_256(redeemer.secret) == secret_hash,
        tagged_values_out_match(
          tx.outputs,
          ExpectedPayment(
            beneficiary,
            merge(value_in.value, negate(deposit_amount)),
          ),
          ExpectedPayment(resolver, deposit_amount),
          ref,
        ),
      }
    } else if resolver_unlock < low && high <= public_unlock {
      //Here any resolver wants to proceed using the secret to get the deposit.
      and {
        blake2b_256(redeemer.secret) == secret_hash,
        tagged_values_out_match(
          tx.outputs,
          ExpectedPayment(
            beneficiary,
            merge(value_in.value, negate(deposit_amount)),
          ),
          ExpectedPayment(redeemer.resolver, deposit_amount),
          ref,
        ),
      }
    } else if public_unlock < low && high < resolver_cancellation {
      //Here the resolver wants to cancel to get the deposit back.
      tagged_values_out_match(
        tx.outputs,
        ExpectedPayment(
          beneficiary,
          merge(value_in.value, negate(deposit_amount)),
        ),
        ExpectedPayment(resolver, deposit_amount),
        ref,
      )
    } else if resolver_cancellation < low {
      //Here any resolver wants to cancel to get the deposit.
      tagged_values_out_match(
        tx.outputs,
        ExpectedPayment(
          beneficiary,
          merge(value_in.value, negate(deposit_amount)),
        ),
        ExpectedPayment(redeemer.resolver, deposit_amount),
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
