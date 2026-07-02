"""Friendly-handle generation.

A handle like ``zn-palm-dog-cherry`` is directory sugar: unique, human, easy to
say over the phone. It is NOT the identity — the ZC- ID remains the
cryptographic commitment, and clients still verify the pubkey against it after
resolving a handle. Three words carry ~26 bits; treat them like a username,
not like a key fingerprint.

Words are picked deterministically from the ID hash so re-registration of the
same key yields the same handle; collisions fall back to a numeric suffix.
"""

import hashlib

# ~330 short, concrete, easy-to-spell nouns. Deliberately no adjectives and no
# words that form awkward pairs.
WORDS = [
    "acorn", "amber", "anchor", "apple", "apron", "arrow", "aspen", "atlas",
    "badge", "bagel", "bamboo", "banjo", "barn", "basil", "beach", "bean",
    "bear", "beet", "bell", "berry", "birch", "bison", "boat", "bolt",
    "book", "boot", "bottle", "bow", "box", "bread", "breeze", "brick",
    "bridge", "brook", "broom", "brush", "bucket", "bud", "bugle", "bunny",
    "butter", "button", "cabin", "cactus", "cake", "camel", "candle", "canoe",
    "canyon", "carrot", "castle", "cat", "cedar", "chair", "chalk", "cherry",
    "chess", "chest", "chime", "cider", "clam", "clay", "cliff", "clock",
    "cloud", "clover", "coal", "coast", "cocoa", "comet", "compass", "coral",
    "cork", "corn", "cotton", "cove", "crab", "crane", "creek", "cricket",
    "crow", "crown", "cup", "curtain", "daisy", "dawn", "deer", "delta",
    "desk", "dew", "dice", "dime", "dish", "dog", "dome", "door",
    "dove", "dragon", "drum", "duck", "dune", "eagle", "earth", "echo",
    "eel", "egg", "elk", "elm", "ember", "fable", "falcon", "fawn",
    "feather", "fern", "ferry", "field", "fig", "finch", "fire", "fish",
    "flag", "flame", "flint", "flute", "fog", "forest", "fox", "frog",
    "frost", "galaxy", "garden", "garlic", "gate", "gecko", "gem", "ginger",
    "glacier", "glass", "globe", "glove", "goat", "goose", "grape", "grass",
    "grove", "guitar", "gull", "hammer", "harbor", "harp", "hawk", "hazel",
    "heron", "hill", "hive", "honey", "hook", "horn", "horse", "house",
    "ice", "ink", "iris", "iron", "island", "ivy", "jade", "jar",
    "jasmine", "jet", "jewel", "juniper", "kayak", "kettle", "key", "kite",
    "kiwi", "koala", "lagoon", "lake", "lamp", "lantern", "leaf", "ledge",
    "lemon", "lentil", "lily", "lime", "linen", "lion", "lizard", "llama",
    "lobster", "log", "lotus", "lynx", "magnet", "mango", "maple", "marble",
    "meadow", "melon", "mesa", "mint", "mirror", "mole", "moon", "moose",
    "moss", "moth", "mouse", "mule", "mushroom", "nest", "net", "newt",
    "night", "nutmeg", "oak", "oasis", "oat", "ocean", "olive", "onion",
    "opal", "orange", "orbit", "orchid", "otter", "owl", "ox", "oyster",
    "palm", "panda", "pansy", "paper", "peach", "pear", "pearl", "pebble",
    "pecan", "penguin", "peony", "pepper", "piano", "pine", "pigeon", "planet",
    "plum", "pond", "pony", "poppy", "prairie", "prism", "pumpkin", "quail",
    "quartz", "quill", "rabbit", "raccoon", "raft", "rain", "raisin", "rake",
    "raven", "reef", "reed", "ridge", "river", "robin", "rocket", "roof",
    "rope", "rose", "rowan", "ruby", "rye", "saddle", "sage", "sail",
    "salmon", "sand", "sapphire", "scarf", "seal", "seed", "shell", "ship",
    "shore", "shovel", "silk", "silver", "sky", "sled", "slope", "snail",
    "snow", "sock", "sofa", "soil", "sparrow", "spice", "spider", "spoon",
    "spring", "spruce", "squash", "star", "stone", "stork", "storm", "stove",
    "straw", "stream", "sugar", "summit", "sun", "swan", "table", "talon",
    "tea", "teal", "tent", "thistle", "thorn", "tiger", "timber", "toad",
    "tomato", "torch", "tortoise", "trail", "train", "tree", "trout", "tulip",
    "tuna", "tundra", "turnip", "turtle", "vale", "valley", "vanilla", "vase",
    "velvet", "vine", "violet", "walnut", "walrus", "wave", "wheat", "whale",
    "willow", "wind", "wolf", "wren", "yarn", "zebra",
]

PREFIX = "zn"


def looks_like_handle(raw: str) -> bool:
    parts = raw.strip().lower().replace(" ", "-").split("-")
    return len(parts) >= 3 and parts[0] == PREFIX


def normalize_handle(raw: str) -> str:
    return "-".join(p for p in raw.strip().lower().replace(" ", "-").split("-") if p)


def candidate_handles(zeon_id: str):
    """Deterministic candidates for a given ID: the word triple, then the same
    triple with growing numeric suffixes for the (rare) collision case."""
    seed = hashlib.blake2b(zeon_id.encode(), digest_size=8).digest()
    words = [
        WORDS[int.from_bytes(seed[i : i + 2], "big") % len(WORDS)]
        for i in (0, 2, 4)
    ]
    base = f"{PREFIX}-{'-'.join(words)}"
    yield base
    n = int.from_bytes(seed[6:8], "big") % 90 + 10
    while True:
        yield f"{base}-{n}"
        n += 1
