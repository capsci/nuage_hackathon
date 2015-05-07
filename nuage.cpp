
// Access Control List

#include<iostream>
#include<string.h>
#include<stdlib.h>

using namespace std;

// structure to store rule
typedef struct rule
{
	string sourceIP;
	string destIP;
	string protocol;
	string sourcePort;
	string destPort;
	string priority;
	string action;
	struct rule *next;
}node;

// structure to headers for multiple ACLs
typedef struct acl
{
	string name;
	string action;
	rule *head;
	struct acl *next;
}acl;

// pointer to first ACL
acl *A;

// create a new ACL list
void Acl_list_create(string name, string action)
{
	cout<<"Create"<<endl;
	acl *newAcl;
	newAcl = new acl;
	newAcl->name = name;
	newAcl->action = action;
	newAcl->head = NULL;
	newAcl->next = NULL;
	cout<<"Find"<<endl;
	if(A==NULL)
	{
		cout<<"Adding first node";
		A=newAcl;
	}
	else
	{
		cout<<"Adding another node";
		acl *temp;
		temp = A;
		while(temp->next!=NULL)
		{
			temp = temp->next;
		}
		temp->next = newAcl;
	}
}

// adds rule to ACL list
bool Acl_add_rule(string name, string srcIP, string destIP, string protocol, string srcPort, string destPort, string priority, string action)
{
	acl *temp;
	temp = A;
	int foundList = 0;
	while(temp!=NULL)
	{
		if(temp->name==name)
		{
			foundList = 1;
			break;
		}
		 temp = temp->next;
	}
	if(foundList == 0){
		cout<<"List "<<name<<" does NOT exist"<<endl;
		return false;
	}
	rule *newRule;
	newRule = new rule;
	newRule->sourceIP = srcIP;
	newRule->destIP = destIP;
	newRule->protocol = protocol;
	newRule->sourcePort = srcPort;
	newRule->destPort = destPort;
	newRule->priority = priority;
	newRule->action = action;

	rule *tmp = temp->head;
	if(tmp==NULL)
	{
		cout<<"FirstRule"<<endl;
		temp->head = newRule;
	}
	else
	{
		cout<<"Adding another node";
		rule *temp1;
		temp1 = temp->head;
		while(temp1->next!=NULL)
		{
			temp1 = temp1->next;
		}
		temp1->next = newRule;
	}
	return true;
}

// print ACL
void printAcl()
{
	cout<<"Printing"<<endl;
	acl *temp;
	temp = A;
	while(temp!=NULL)
	{
		cout<<temp->name<<","<<temp->action<<endl;
		rule *t1;
		t1=temp->head;
		while(t1!=NULL)
		{
			cout<<"\t"<<t1->sourceIP<<","<<t1->destIP<<","<<t1->protocol<<endl;
			t1=t1->next;
		}
		temp=temp->next;
	}
}

// check if incoming packet is in accordance with either of the rules
bool checkRule(rule *r,string srcIP, string destIP, string protocol, string srcPort, string destPort)
{
	bool rule = true;
	if(r->sourceIP!="*" && r->sourceIP!=srcIP)
	{
		rule = false;
	}
	if(r->destIP!="*" && r->destIP!=destIP)
	{
		rule = false;
	}
	if(r->protocol!="*" && r->protocol!=protocol)
	{
		rule = false;
	}
	if(r->sourcePort!="*" && r->sourcePort!=srcPort)
	{
		rule = false;
	}
	if(r->destPort!="*" && r->destPort!=destPort)
	{
		rule = false;
	}
	return rule;
}

// get packet and check it against each ACL
rule* Acl_check_packet(string name,string srcIP,string destIP, string protocol, string srcPort, string destPort)
{
	cout<<"Check"<<endl;
	acl *temp;
	temp = A;
	while(temp!=NULL)
	{
		if(temp->name==name)
		{
			cout<<"ACL found"<<endl;
			rule *t1;
			t1 = temp->head;
			while(t1!=NULL)
			{
				t1= t1->next;
				if(checkRule(t1,srcIP,destIP,protocol,srcPort,destPort))
				{
					cout<<"Rule Satisfied!"<<endl;
					return t1;
				}
			}
			break;
		}
		temp = temp->next;
	}
	cout<<"No ACL/rule found"<<endl;
	rule *r;
	r = new rule;
	r->sourceIP = "-1";
	cout<<"Rule NOT satisfied"<<endl;
	return r;
}

// sample test case
void testCase()
{
	cout<<"TestCase"<<endl;
	rule* retVal;
	retVal = Acl_check_packet("ACL_A","3.4.5.6","4.5.6.7","TCP","8080","12456");
	cout<<"Check"<<endl;
	if(retVal->sourceIP!="-1")
	{
		cout<<"Rule Action:"<<retVal->action<<","<<retVal->priority<<endl;
	}
	else
	{
		cout<<"No valid rule found"<<endl;
	}
}

// call main
int main()
{
	A = NULL;
	Acl_list_create("ACL_A","Allow");
	Acl_list_create("ACL_B","Deny");
	Acl_list_create("ACL_C","Allow");
	Acl_add_rule("ACL_A","SIP","DIP","Proto","SrcP","DestP","3","Act");
	Acl_add_rule("ACL_A","SIP1","DIP","Proto","SrcP","DestP","3","Act");
	Acl_add_rule("ACL_B","SIP2","DIP","Proto","SrcP","DestP","3","Act");
	Acl_add_rule("ACL_C","SIP3","DIP","Proto","SrcP","DestP","3","Act");
	Acl_add_rule("ACL_A","SIP4","DIP","Proto","SrcP","DestP","3","Act");
	printAcl();
	testCase();
	free(A);
	return 1;
}
