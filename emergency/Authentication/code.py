# def high():
#     stored_list = []
#     for _ in range(int(input())):
        
#         name = input()
#         score = float(input())
#         stored_list.append([name, score])
#         print(stored_list)
#         dict_name = dict(stored_list)
#         sort_name = sorted(set(dict_name.values()))
#         second_lowest=[name for name, score in stored_list if score ==sort_name[1] ]
#         second_lowest.sort()
#         for name in second_lowest:
#             print(name)
# dee = high()
# print(dee)



if __name__ == '__main__':
    n = int(input())
    student_marks = {}
    for _ in range(n):
        name, *line = input().split()
        scores = list(map(float, line))
        student_marks[name] = scores
    query_name = input()
    output = list(student_marks[query_name])    
    per = sum(output)/len(output)
    a = format(per, '.2f')
    print(a)