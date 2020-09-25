from agora.keys import PublicKey
from agora.solana.memo.program import memo_instruction, decompile_memo
from agora.solana.transaction import Transaction


class TestMemoProgram:
    def test_memo_progam(self):
        data = 'somedata'
        i = memo_instruction(data)

        assert i.data.decode('utf-8') == data

        tx = Transaction.unmarshal(Transaction.new(PublicKey(bytes(32)), [i]).marshal())
        memo = decompile_memo(tx.message, 0)
        assert memo.data.decode('utf-8') == data
