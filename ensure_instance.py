# small helper to ensure instance folder exists at runtime
import os
inst = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(inst, exist_ok=True)
