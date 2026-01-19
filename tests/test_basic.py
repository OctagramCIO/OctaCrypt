from octacrypt.core.crypto_engine import CryptoEngine

engine = CryptoEngine()

data = engine.encrypt("Octagram vive")
print("Cifrado:", data)

original = engine.decrypt(data)
print("Descifrado:", original)
