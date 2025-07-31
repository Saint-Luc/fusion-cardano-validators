use aiken/cbor.{serialise}
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/address.{PaymentCredential}
use cardano/assets.{
  AssetName, Lovelace, PolicyId, ada_asset_name, ada_policy_id, quantity_of,
}
use cardano/transaction.{DatumHash, InlineDatum, Output, OutputReference}

pub type ExpectedPayment {
  credential: PaymentCredential,
  policy_id: PolicyId,
  asset_name: AssetName,
  amount: Int,
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

//Looks for all the tagged outputs, sums the values that go to the given addresses,
//and finally compares them to the given (expected) values.
pub fn tagged_values_out_match(
  outputs: List<Output>,
  beneficiary: ExpectedPayment,
  resolver: PaymentCredential,
  deposit_amount: Lovelace,
  ref: OutputReference,
) -> Bool {
  let (beneficiary_amount, resolver_amount) =
    list.foldl(
      outputs,
      (0, 0),
      fn(output, acc) {
        let is_tagged = is_tagged(output, ref)
        if is_tagged && output.address.payment_credential == beneficiary.credential {
          (
            acc.1st + quantity_of(
              output.value,
              beneficiary.policy_id,
              beneficiary.asset_name,
            ),
            acc.2nd,
          )
        } else if is_tagged && output.address.payment_credential == resolver {
          (
            acc.1st,
            acc.2nd + quantity_of(output.value, ada_policy_id, ada_asset_name),
          )
        } else {
          acc
        }
      },
    )
  and {
    beneficiary_amount == beneficiary.amount,
    resolver_amount == deposit_amount,
  }
}
