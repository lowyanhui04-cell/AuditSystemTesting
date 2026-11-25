# EndpointLens 2.2 — one Admin EXE, one Super Admin website

## Test on your own Windows computer first

1. Extract this entire ZIP. Open PowerShell in the extracted folder, alongside EndpointLens.exe. Run `.\Start-Central.ps1`. If Windows blocks the downloaded script, review it in a text editor and use the equivalent manual commands in `Source/README.md`. The launcher uses the already installed .NET SDK's certificate tool and the compiled EXE.
2. Set the password the audit operator will use for this server session. The username is **audit-admin**. Keep that PowerShell window open.
3. Open **https://localhost:5443**. Create or use your separate Super Admin account. This website shows every registered computer.
4. Double-click **EndpointLens.exe** in the same ZIP. The local dashboard will open. Sign in as **audit-admin**, with the password from step 2.
5. Click **Start audit**. The computer registers automatically at sign-in. Its new audit is saved locally, then uploaded. Refresh the central dashboard to see its score and history.
6. To delete an endpoint, choose **Delete** in its row on the central Overview, then confirm. This deletes central history. The PC can register again on a future Admin sign-in.

## Use on multiple PCs

Set Company:CentralAddress in the included appsettings.json to the reachable HTTPS address of your central server. Share the same EXE and the same appsettings.json with all authorized auditors. Neither file includes an upload password. The Admin uses the operator account set on the central server. See Source/README.md for the central network certificate and launch configuration.

After an Admin session is connected, pending audits are retained locally if the network goes down. They resume uploading when the connection recovers or after the next successful Admin sign-in. An initial Admin sign-in requires the server to be reachable.
