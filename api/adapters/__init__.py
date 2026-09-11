"""Adapters between the deployed wire contracts and the core boundary.

These translate; they do not decide. An adapter turns a request that the
API already authenticated into the vendor-neutral representation the core
authority boundary reasons about, and turns a core decision back into the
wire vocabulary the deployed clients expect. No adapter widens
permissions, and none of them read identity from the request body.
"""
