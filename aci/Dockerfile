FROM prefecthq/prefect:2-python3.9

COPY credential_helper.sh /opt/prefect/
COPY retrieve_secrets.py /opt/prefect/
COPY requirements.txt /opt/prefect/flows/
COPY entrypoint.sh /opt/prefect/

RUN chmod +x /opt/prefect/credential_helper.sh \ 
    && chmod +x /opt/prefect/entrypoint.sh

RUN pip install -r /opt/prefect/flows/requirements.txt

RUN git config --global credential.helper "/bin/bash /opt/prefect/credential_helper.sh"

ENTRYPOINT [ "/opt/prefect/entrypoint.sh" ]