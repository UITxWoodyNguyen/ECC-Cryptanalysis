import sys
from curves.ecc import *
def Exhaustive_search(P: Point, Q:Point, Bounds: int)-> int:
    # P = n.Q
    n=1
    while n < Bounds:
        if (P == n*Q):
            return n
        n+=1

