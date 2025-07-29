use aiken/fuzz
use aiken/interval.{Finite, Interval, IntervalBound, NegativeInfinity, PositiveInfinity}

//Expects the interval to have two finite bounds, then returns those bounds as inclusive, offsetting them
//appropriately if they are not.
pub fn expect_finite_interval(interval: Interval<Int>) -> (Int, Int) {
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



test finite_interval(bounds via fuzz.tuple(fuzz.int(), fuzz.int())) {
    let interval = Interval(IntervalBound(Finite(bounds.1st), True), IntervalBound(Finite(bounds.2nd), True))
    let (low, high) = expect_finite_interval(interval)
    and {
        low == bounds.1st,
        high == bounds.2nd,
    }
}

fn make_infinity(side: Bool) -> IntervalBound<Int> {
    when side is {
        True -> IntervalBound(PositiveInfinity, False)
        False -> IntervalBound(NegativeInfinity, False)
    }
}

test infinite_interval(infinity_sides via fuzz.tuple(fuzz.bool(), fuzz.bool())) fail {
    let interval = Interval(make_infinity(infinity_sides.1st), make_infinity(infinity_sides.2nd))
    expect _ = expect_finite_interval(interval)
    True
}
