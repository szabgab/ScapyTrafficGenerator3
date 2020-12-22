import json
jsonfile = 'agents.json'
jsonfile2 = 'agents2.json'
class AgentParser():
    def __init__(self):
        self.agentstring = None
        self.agentStringList = []
        
    def Show_dictionary(self,
                        DICT):
        print json.dumps(DICT, sort_keys=True, indent=4, separators=(',', ': '))
    def NarrowList(self,
                   DescriptionString = None):
        #print 'searching for', DescriptionString
        removallist = []
        found = False
        LIST = []
        if isinstance(DescriptionString, str):
            for AGENT in self.agentList:
                #print 'is', DescriptionString.lower(), 'in', str(AGENT).lower()
                if str(DescriptionString).lower() in str(AGENT).lower():
                    try:
                        for agent in AGENT.get('useragent'):
                            #print 'is', DescriptionString.lower(), 'in', str(agent).lower()
                            if DescriptionString.lower() in str(agent).lower():
                                #print 'found', DescriptionString.lower() , 'in',  str(agent).lower()
                                LIST.append(agent)
                                found = True
                            else:
                                removallist.append(AGENT)
                    except:
                        removallist.append(AGENT)      
            
        else:
            print DescriptionString, 'not a string'

            
        for remove in removallist:
            try:
                self.agentList.remove(remove)
            except:
                pass
                #print 'cant remove'
                
        return LIST

    #will return the first string found matching the set of arguments for now
    def FindAgentStrings(self,
                  *args
                  ):
        #self.agentList= json.load(open(jsonfile))['user-agents']['user-agent']
        self.agentList= json.load(open(jsonfile2))['useragentswitcher']['folder']
        for arg in args:
            #print 'narrowing down list for' ,arg
            LIST = self.NarrowList(DescriptionString = arg)

      
        for agent in LIST:
            agentstring = agent.get('@useragent')
            if agentstring != None:
                #print 'first match found in ', agent
                #print 'user agent string', str(agentstring)
                return [str(agentstring)]

        return []


            
   
