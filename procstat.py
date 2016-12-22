f = open('stats.csv','r')
s = [0.0]*5
c = 0
for line in f:
	c += 1
	if line.strip() == "":
		continue
	row = line.split(",")
	row = [float(x) for x in row]
	for i in range(len(row)):
		s[i] += row[i]
s = [x/c for x in s]
print s