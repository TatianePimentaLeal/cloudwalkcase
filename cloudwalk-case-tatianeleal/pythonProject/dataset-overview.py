with open("test-dataset.csv","r") as file:
    file_teste = file.read()
dataset = file_teste.split()
print(dataset)