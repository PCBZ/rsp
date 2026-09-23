# Deploy notes

The staging deploy is a single command; production is the same command with a
different profile and a second pair of eyes.

    ./deploy --env staging --region eu-west-1

The profile is read from the environment. Someone pasted the raw value into
this page during an incident and it was never taken out:

    AWS_ACCESS_KEY_ID=AKIA47CQZHT2MVPF3JXB

Rotate that before the next release. It is in the incident channel too, which
is a separate problem.
