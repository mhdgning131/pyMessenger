def main():
    spacecraft={"name":"Voyager 1","distance":163}
    print(create_report(spacecraft))

def create_report(spacecraft):
   return f"""   ========= REPORT =========
   Name: {spacecraft["name"]}
   Distance: {spacecraft["distance"]} AU
 
   ==========================
   """
 
main()
 
"""
report1.py
 1 defmain():
 2 spacecraft={"name":"James Webb Space Telescope"}
 3 print(create_report(spacecraft))
 4
 5
 6 defcreate_report(spacecraft):
 7 returnf""""""
     ========= REPORT =========
   Name: {spacecraft["name"]}
   Distance: {spacecraft["distance"]} AU
   ==========================
 """"""
main()
"""

"""
1 defmain():
 2 spacecraft={"name":"James Webb Space Telescope"}
 3 print(create_report(spacecraft))
 4
 5
 6 defcreate_report(spacecraft):
 7 returnf"""
"""
    ========= REPORT =========
    Name: {spacecraft.get("name","Unknown")}
    Distance: {spacecraft.get("distance","Unknown")} AU
    ==========================
 """""" main()
"""