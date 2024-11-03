from luov import LUOV

def menu():
    print("Selecciona una versión de LUOV:")
    print("1. LUOV-7-57-197")
    print("2. LUOV-7-83-283")
    print("3. LUOV-7-110-374")
    print("4. LUOV-47-42-182")
    print("5. LUOV-61-60-261")
    print("6. LUOV-79-76-341")

    option = input("Ingrese el número de la opción: ")
    
    if option == '1':
        r, m, v = 7, 57, 197
    elif option == '2':
        r, m, v = 7, 83, 283
    elif option == '3':
        r, m, v = 7, 110, 374
    elif option == '4':
        r, m, v = 47, 42, 182
    elif option == '5':
        r, m, v = 61, 60, 261
    elif option == '6':
        r, m, v = 79, 76, 341
    else:
        print("Opción inválida, selecciona de nuevo.")
        return menu()
    
    return r, m, v

if __name__ == "__main__":
    r, m, v = menu()

    luov = LUOV(r, m, v)

    private_seed = luov.generate_private_seed()
    
    public_key, private_seed = luov.key_generation(private_seed)

    with open("publicKey", "wb") as f:
        f.write(public_key)
    
    print("Claves generadas y guardadas exitosamente.")