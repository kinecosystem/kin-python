from enum import IntEnum

from agoraapi.common.v4 import model_pb2 as model_pb


class Commitment(IntEnum):
    """Used to indicate to Solana nodes which bank state to query.
    See: https://docs.solana.com/apps/jsonrpc-api#configuring-state-commitment

    RECENT: The node will query its most recent block.
    SINGLE: The node will query the most recent block that has been voted on by supermajority of the cluster.
    ROOT: The node will query the most recent block having reached maximum lockout on this node.
    MAX: The node will query the most recent block confirmed by supermajority of the cluster as having reached maximum
        lockout.
    """
    RECENT = 0
    SINGLE = 1
    ROOT = 2
    MAX = 3

    def to_proto(self) -> model_pb.Commitment:
        if self == Commitment.RECENT:
            return model_pb.Commitment.RECENT
        if self == Commitment.SINGLE:
            return model_pb.Commitment.SINGLE
        if self == Commitment.ROOT:
            return model_pb.Commitment.ROOT
        if self == Commitment.MAX:
            return model_pb.Commitment.MAX

        raise ValueError(f'unknown commitment value of {self}')
