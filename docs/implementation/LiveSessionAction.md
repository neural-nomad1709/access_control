
## How to use the tool

    Step 1) open terminal and punchin the command. In your terminal (once, keep it open)

        uv run ac connect <<hops tage name from invetory.yaml>>

    Type the SSH password when prompted. This process is the session — closing it ends the session.
    Once the session is active to the target server 

    step 2) perform following steps on new terminal 

In this conversation, just tell me what you want done. I don't need anything "passed in" — I'll run, in order:

1. Confirm the session is actually live and attached to the right box:
uv run ac status <<hops tage name from invetory.yaml>>
uv run ac verify <<hops tage name from invetory.yaml>> --expect-hostname dmz-stg01
2. See what's permitted on it:
uv run ac ops --host <<hops tage name from invetory.yaml>>
3. Preview before running anything destructive/state-changing:
uv run ac preview <<hops tage name from invetory.yaml>> <operation> -p key=value
4. Then run it, with your explicit confirmation:
uv run ac run <<hops tage name from invetory.yaml>> <operation> -p key=value --confirm