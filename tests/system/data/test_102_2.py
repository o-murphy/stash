import os
import time

for i in range(5):
    print(f"{os.path.basename(__file__)}")
    time.sleep(0.5)
