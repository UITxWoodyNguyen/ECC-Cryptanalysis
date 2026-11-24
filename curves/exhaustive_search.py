from curves.ecc import Point


def exhaustive_search(P: Point, Q: Point, bounds: int) -> int:
    """Tìm số nguyên n sao cho P = n * Q bằng vét cạn cộng dồn."""
    if P.curve != Q.curve:
        raise ValueError("P and Q must be on the same curve")
    if P.is_infinity:
        return 0
    if Q.is_infinity:
        raise ValueError("Generator point Q cannot be at infinity")

    R = Q
    for n in range(1, bounds + 1):
        if R == P:
            return n
        R = R + Q

    raise ValueError(f"Value not found within bounds (1..{bounds}). Increase bounds.")