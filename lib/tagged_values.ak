use aiken/cbor.{serialise}
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/address.{PaymentCredential}
use cardano/assets.{Value, merge, zero}
use cardano/transaction.{DatumHash, InlineDatum, Output, OutputReference}

pub type ExpectedPayment {
  credential: PaymentCredential,
  value: Value,
}

fn is_tagged(output: Output, ref: OutputReference) -> Bool {
  when output.datum is {
    InlineDatum(datum) ->
      if datum is OutputReference {
        datum == ref
      } else {
        False
      }
    DatumHash(datum_hash) -> datum_hash == blake2b_256(serialise(ref))
    _ -> False
  }
}

pub fn tagged_values_out_match(
  outputs: List<Output>,
  beneficiary: ExpectedPayment,
  resolver: ExpectedPayment,
  ref: OutputReference,
) -> Bool {
  let (beneficiary_value, resolver_value) =
    list.foldl(
      outputs,
      (zero, zero),
      fn(output, acc) {
        let is_tagged = is_tagged(output, ref)
        if is_tagged && output.address.payment_credential == beneficiary.credential {
          (merge(acc.1st, output.value), acc.2nd)
        } else if is_tagged && output.address.payment_credential == resolver.credential {
          (acc.1st, merge(acc.2nd, output.value))
        } else {
          acc
        }
      },
    )
  and {
    beneficiary_value == beneficiary.value,
    resolver_value == resolver.value,
  }
}
