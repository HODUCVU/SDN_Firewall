import time 

current_time = time.time()
last_time = current_time

count = 0;

while(100):
    ctime = time.time()
    if(ctime - last_time >= 10):
        count+=1 
        print(count)
        last_time = current_time

        print(ctime, " -- ", current_time)
    totaltime = round((ctime - current_time),2)
    print(totaltime)
    print("current_time: ", current_time, " -- ctime: ", ctime)
    # print(".", end='\0')
