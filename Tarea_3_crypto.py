# Daniel Felipe Hincapie Nieto
# Seguridad en el desarrollo de software
# Uniminuto, Especialización en desarrollo de software
# Semana 3, 28 de Julio de 2025

#--------------------------------------------------------------------------------------------
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ---------------------------------------
# Generar las claves privada y pública
# Se generan las claves de forma automatica
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Mensaje original
mensaje = b"Cifrado de la tarea para la semana 3"

# Se firmar el mensaje con la clave privada
firma = private_key.sign(
    mensaje,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verificar la firma con la clave pública, se crea una validación de seguridad con try-except para el manejo
# de excepciones y en este caso si la firma no es la autentica
try:
    public_key.verify(
        firma,
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Firma correcta")
except Exception as e:
    print("Firma inválida:", str(e))

# Cifrar el mensaje con la clave pública
mensaje_cifrado = public_key.encrypt(
    mensaje,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Mensaje cifrado: ", mensaje_cifrado.hex())

# ------------------------------------------------------------------------
# Descifrar el mensaje con la clave privada
mensaje_descifrado = private_key.decrypt(
    mensaje_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("--------------------------------------------------------")
print("Mensaje descifrado: ", mensaje_descifrado.decode())
