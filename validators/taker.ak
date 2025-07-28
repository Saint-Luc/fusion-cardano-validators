use aiken/cbor.{serialise}
use aiken/collection/list
use aiken/crypto.{blake2b_256, Blake2b_256, Hash}
use aiken/interval.{Interval, IntervalBound, Finite}

use cardano/address.{PaymentCredential}
use cardano/assets.{Value, merge, negate, zero}
use cardano/transaction.{DatumHash, InlineDatum, Output, OutputReference, Transaction}

pub type TakerDatum {
    beneficiary: PaymentCredential,
    resolver: PaymentCredential,

    deposit_amount: Value,

    secret_hash: Hash<Blake2b_256, ByteArray>,

    //All variables below correspond to the last block of the named period, inclusive
    finality_lock: Int,
    resolver_unlock: Int,
    public_unlock: Int,
}

pub type Redeemer {
    secret: ByteArray,
    resolver: PaymentCredential,
}

//Expects the interval to have two finite bounds, and returns those bounds as inclusive (offsetting if not).
fn expect_finite_interval(interval: Interval<Int>) -> (Int, Int) {
    expect Interval{
        lower_bound: IntervalBound{bound_type: Finite(low), is_inclusive: low_inclusive},
        upper_bound: IntervalBound{bound_type: Finite(high), is_inclusive: high_inclusive},
    } = interval
    let low = when low_inclusive is {
        False -> low + 1
        True -> low
    }
    let high = when high_inclusive is {
        True -> high
        False -> high - 1
    }
    (low, high)
}

pub type ExpectedPayment {
    credential: PaymentCredential,
    value: Value,
}

fn is_tagged(output: Output, ref: OutputReference) -> Bool {
    when output.datum is {
        InlineDatum(datum) -> if datum is OutputReference {
            datum == ref
        } else {
            False
        }
        DatumHash(datum_hash) -> datum_hash == blake2b_256(serialise(ref))
        _ -> False
    }
}

fn tagged_values_out_match(
    outputs: List<Output>,
    beneficiary: ExpectedPayment,
    resolver: ExpectedPayment,
    ref: OutputReference,
) -> Bool {
    let (beneficiary_value, resolver_value) = list.foldl(
        outputs,
        (zero, zero),
        fn(output, acc) {
            if is_tagged(output, ref) {
                if output.address.payment_credential == beneficiary.credential {
                    (merge(acc.1st, output.value), acc.2nd)
                } else if output.address.payment_credential == resolver.credential {
                    (acc.1st, merge(acc.2nd, output.value))
                } else {
                    acc
                }
            } else {
                acc
            }
        }
    )
    and {
        beneficiary_value == beneficiary.value,
        resolver_value == resolver.value,
    }
}

validator taker_escrow {
    spend(datum: Option<TakerDatum>, redeemer: Redeemer, ref: OutputReference, tx: Transaction) {
        expect Some(TakerDatum{
            beneficiary,
            resolver,
            deposit_amount,
            secret_hash,
            finality_lock,
            resolver_unlock,
            public_unlock,
        }) = datum

        let (low, high) = expect_finite_interval(tx.validity_range)

        expect Some(value_in) = list.find(tx.inputs, fn(input) { input.output_reference == ref })
        let value_in = value_in.output

        if finality_lock < low && high <= resolver_unlock {
            //Here the selected resolver wants to proceed using the secret to get the deposit back.
            and {
                blake2b_256(redeemer.secret) == secret_hash,
                tagged_values_out_match(
                    tx.outputs,
                    ExpectedPayment(beneficiary, merge(value_in.value, negate(deposit_amount))),
                    ExpectedPayment(resolver, deposit_amount),
                    ref,
                )
            }
        } else if resolver_unlock < low && high <= public_unlock {
            //Here any resolver wants to proceed using the secret to get the deposit.
            and {
                blake2b_256(redeemer.secret) == secret_hash,
                tagged_values_out_match(
                    tx.outputs,
                    ExpectedPayment(beneficiary, merge(value_in.value, negate(deposit_amount))),
                    ExpectedPayment(redeemer.resolver, deposit_amount),
                    ref,
                )
            }
        } else if public_unlock < low {
            //Here the resolver wants to cancel to get the deposit and the funds back.
            tagged_values_out_match(
                tx.outputs,
                ExpectedPayment(beneficiary, merge(value_in.value, negate(deposit_amount))),
                ExpectedPayment(resolver, deposit_amount),
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
