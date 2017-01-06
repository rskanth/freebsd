#include <stdio.h>

int
client_create_test()
{
       struct p9_client *clnt;

       clnt = p9_client_create(NULL);

        if (clnt = NULL) error("client malloc failed ");

       if(clnt->trans_mod == NULL) {
               error("trans_mod init failed ..\n");
       }

       return clnt;
}
       
void dump_fid(struct p9_fid *fid)
{
       printf("\n",);
}

int
client_attach_test(struct p9_client *clnt)
{
        struct p9_fid *pfid;

        /* This even tests the client_request API call*/
        pfid = p9_client_attach(clnt);
        if (pfid == NULL) error(" client attach failed ..\n");
       
       dump_fid(pfid);
}

int main() {

        struct p9_client *clnt;
       

        clnt = client_create_test();

       /* Ideally this should hav tested the client_requet*/
        client_attach_test(clnt);

       /* This should create the request, map the tc,fc
       submit the request and get the results back */
       p9_client_request();
}
