from .utils import Reader, Writer, to_hex, to_bytes
from .hash import hash256
from .service import Service

# from .chain_tracker import ChainTracker
from typing import List, Dict, Optional, Union, TypedDict


class MerkleLeaf(TypedDict, total=False):
    offset: int
    hash_str: str
    txid: bool
    duplicate: bool


class MerklePath:
    """
    Represents a Merkle Path, which is used to provide a compact proof of inclusion for a
    transaction in a block. This class encapsulates all the details required for creating
    and verifying Merkle Proofs.

    Attributes:
        block_height (int): The height of the block in which the transaction is included.
        path (List[List[MerkleLeaf]]): A tree structure representing the Merkle Path,
            with each level containing information about the nodes involved in constructing the proof.

    Example:
        # Creating and verifying a Merkle Path
        merkle_path = MerklePath.from_hex('...')
        is_valid = await merkle_path.verify(txid, chain_tracker)

    Description:
        The MerklePath class is useful for verifying transactions in a lightweight and efficient manner without
        needing the entire block data. This class offers functionalities for creating, converting,
        and verifying these proofs.
    """

    def __init__(self, block_height: int, path: List[List[MerkleLeaf]]):
        self.block_height = block_height
        self.path = path

        # store all of the legal offsets which we expect given the txid indices.
        legal_offsets = [set() for _ in range(len(self.path))]
        for height, leaves in enumerate(self.path):
            if not leaves:
                raise ValueError(f"Empty level at height: {height}")

            offsets_at_this_height = set()
            for leaf in leaves:
                if leaf["offset"] in offsets_at_this_height:
                    raise ValueError(
                        f"Duplicate offset: {leaf['offset']}, at height: {height}"
                    )
                offsets_at_this_height.add(leaf["offset"])

                if height == 0:
                    if not leaf.get("duplicate"):
                        for h in range(1, len(self.path)):
                            legal_offsets[h].add(leaf["offset"] >> h ^ 1)
                else:
                    if leaf["offset"] not in legal_offsets[height]:
                        legal_offsets_at_height = ", ".join(
                            map(str, legal_offsets[height])
                        )
                        raise ValueError(
                            f"Invalid offset: {leaf['offset']}, at height: {height}, with legal offsets: {legal_offsets_at_height}"
                        )

        root = None
        for idx, leaf in enumerate(self.path[0]):
            if idx == 0:
                root = self.compute_root(leaf.get("hash_str", None))
            if root != self.compute_root(leaf.get("hash_str", None)):
                raise ValueError("Mismatched roots")

    @staticmethod
    def from_hex(hex_str: str) -> "MerklePath":
        """
        Creates a MerklePath instance from a hexadecimal string.

        Args:
            hex_str (str): The hexadecimal string representation of the Merkle Path.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        return MerklePath.from_binary(to_bytes(hex_str, "hex"))

    @staticmethod
    def from_reader(reader: Reader) -> "MerklePath":
        """
        Creates a MerklePath instance from a Reader object.

        Args:
            reader (Reader): The Reader object.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        block_height = reader.read_var_int_num()
        tree_height = reader.read_uint8()
        path = [[] for _ in range(tree_height)]

        for level in range(tree_height):
            try:
                n_leaves_at_this_height = reader.read_var_int_num()
            except:
                n_leaves_at_this_height = 0

            while n_leaves_at_this_height:
                offset = reader.read_var_int_num()
                flags = reader.read_uint8()
                leaf = {"offset": offset}

                if flags & 1:
                    leaf["duplicate"] = True
                else:
                    if flags & 2:
                        leaf["txid"] = True
                    leaf["hash_str"] = to_hex(reader.read(32)[::-1])

                path[level].append(leaf)
                n_leaves_at_this_height -= 1

            path[level].sort(key=lambda l: l["offset"])

        return MerklePath(block_height, path)

    @staticmethod
    def from_binary(bump: bytes) -> "MerklePath":
        """
        Creates a MerklePath instance from a bytes object.

        Args:
            bump (bytes): The binary array representation of the Merkle Path.

        Returns:
            MerklePath: A new MerklePath instance.
        """
        reader = Reader(bump)
        return MerklePath.from_reader(reader)

    def to_binary(self) -> bytes:
        """
        Converts the MerklePath to a binary array format.

        Returns:
            bytes: The binary array representation of the Merkle Path.
        """
        writer = Writer()
        writer.write_var_int_num(self.block_height)
        tree_height = len(self.path)
        writer.write_uint8(tree_height)

        for level in range(tree_height):
            n_leaves = len(self.path[level])
            writer.write_var_int_num(n_leaves)

            for leaf in self.path[level]:
                writer.write_var_int_num(leaf["offset"])
                flags = 0
                if leaf.get("duplicate"):
                    flags |= 1
                if leaf.get("txid"):
                    flags |= 2
                writer.write_uint8(flags)

                if not (flags & 1):
                    writer.write(to_bytes(leaf["hash_str"], "hex")[::-1])

        return writer.to_bytes()

    def to_hex(self) -> str:
        """
        Converts the MerklePath to a hexadecimal string format.

        Returns:
            str: The hexadecimal string representation of the Merkle Path.
        """
        return to_hex(self.to_binary())

    def compute_root(self, txid: Optional[str] = None) -> str:
        """
        Computes the Merkle root from the provided transaction ID.

        Args:
            txid (Optional[str]): The transaction ID to compute the Merkle root for. If not provided,
                the root will be computed from an unspecified branch, and not all branches will be validated!

        Returns:
            str: The computed Merkle root as a hexadecimal string.

        Raises:
            ValueError: If the transaction ID is not part of the Merkle Path.
        """
        if not isinstance(txid, str):
            txid = next(leaf["hash_str"] for leaf in self.path[0] if "hash_str" in leaf)

        index = next(
            (
                leaf["offset"]
                for leaf in self.path[0]
                if leaf.get("hash_str", None) == txid
            ),
            None,
        )
        if not isinstance(index, int):
            raise ValueError(f"This proof does not contain the txid: {txid}")

        def hash_fn(m: str) -> str:
            return to_hex(hash256(to_bytes(m, "hex")[::-1])[::-1])

        working_hash = txid
        for height, leaves in enumerate(self.path):
            offset = index >> height ^ 1
            leaf = next((l for l in leaves if l["offset"] == offset), None)
            if not isinstance(leaf, dict):
                raise ValueError(f"Missing hash for index {index} at height {height}")

            if leaf.get("duplicate"):
                working_hash = hash_fn(working_hash + working_hash)
            elif offset % 2 != 0:
                working_hash = hash_fn(leaf["hash_str"] + working_hash)
            else:
                working_hash = hash_fn(working_hash + leaf["hash_str"])

        return working_hash

    def verify(self, txid: str, service: Service) -> bool:
        # TODO: Should be async once service methods are async as well.
        """
        Verifies if the given transaction ID is part of the Merkle tree at the specified block height.

        Args:
            txid (str): The transaction ID to verify.
            service (Service): The Service instance used to verify the Merkle root.

        Returns:
            bool: True if the transaction ID is valid within the Merkle Path at the specified block height.
        """
        root = self.compute_root(txid)
        return service.is_valid_root_for_height(root, self.block_height)

    def combine(self, other: "MerklePath") -> None:
        """
        Combines this MerklePath with another to create a compound proof.

        Args:
            other (MerklePath): Another MerklePath to combine with this path.

        Raises:
            ValueError: If the paths have different block heights or roots.
        """
        if self.block_height != other.block_height:
            raise ValueError(
                "You cannot combine paths which do not have the same block height."
            )

        root1 = self.compute_root()
        root2 = other.compute_root()
        if root1 != root2:
            raise ValueError(
                "You cannot combine paths which do not have the same root."
            )

        combined_path = []
        for h in range(len(self.path)):
            combined_level = self.path[h] + [
                leaf
                for leaf in other.path[h]
                if leaf["offset"] not in {l["offset"] for l in self.path[h]}
            ]
            for leaf in other.path[h]:
                if "txid" in leaf:
                    for l in combined_level:
                        if l["offset"] == leaf["offset"]:
                            l["txid"] = True
            combined_path.append(combined_level)
        self.path = combined_path
