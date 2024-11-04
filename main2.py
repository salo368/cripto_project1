from main import menu
from luov import LUOV

if __name__ == "__main__":
    r, m, v = menu()

    luov = LUOV(r, m, v)

    private_seed = luov.generate_private_seed()

    m = "hola"

    luov.sign(private_seed, m)