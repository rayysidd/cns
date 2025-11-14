PEERS = ['Alice', 'Bob', 'Charlie', 'David']
PAIRS = [('Alice', 'Bob'), ('Bob', 'Charlie'), ('Charlie', 'David'), ('David', 'Alice')]

# Store your text at the start (copy–paste from your .txt or PDF extract)
with open("harry_potter.txt", "r", encoding="utf-8") as f:
    BASE_TEXT = f.read()

def get_chunk(size=10000, start=0):
    """Return a chunk of BASE_TEXT of given size starting from index `start`."""
    end = min(start + size, len(BASE_TEXT))
    return BASE_TEXT[start:end]

with open('input.txt', 'w', encoding='utf-8') as f:
    offset = 0
    for sender, receiver in PAIRS:
        message = get_chunk(10000, offset)
        offset += 10000  # move to next slice of text for next pair
        f.write(f"Sender: {sender}\n")
        f.write(f"Receiver: {receiver}\n")
        f.write(f"Message: {message}\n\n")

print("Generated messages.txt with actual text chunks from harry_potter.txt")
