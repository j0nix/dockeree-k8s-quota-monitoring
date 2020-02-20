import re
import os
import sys
import time
import json
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings when not validate certificates in https requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from cmreslogging.handlers import CMRESHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)-8s[%(name)s] %(message)s")
logger = logging.getLogger("k8s-quota-moniroring")


class DockerEE:
    def __init__(
        self,
        host,
        username,
        password,
        es_host=None,
        es_port=None,
        es_user=None,
        es_pwd=None,
    ):

        self.host = host
        self.username = username
        self.password = password
        self.token = None

        self.eslog = logging.getLogger("elasticLogger")
        self.eslog.setLevel(logging.DEBUG)

        self.es_host = es_host
        self.es_port = es_port
        self.es_user = es_user
        self.es_pwd = es_pwd

        self.http_headers = {
            "accept": "application/json",
            "content-type": "application/json",
        }

        try:
            self.token = self.getToken()
            if self.token is not None:
                self.http_headers["Authorization"] = "Bearer {}".format(self.token)
                logger.info("Successfully login, got token {}".format(self.token))
            else:
                sys.exit(1)

        except Exception as e:
            logger.error("Problem get auth-token, {}".format(e))
            sys.exit(1)

    def __del__(self):

        try:
            if self.token:
                if self.destroyToken():
                    logger.info("Successfully logout token {}".format(self.token))
            else:
                pass
        except AttributeError:
            pass

    def destroyToken(self):

        if self.token:
            try:
                url = "https://{}/id/logout".format(self.host)
                response = requests.post(url, headers=self.http_headers, verify=False)
            except Exception as e:
                logger.error("SOME ERROR 1, {}".format(getattr(e, "message", repr(e))))

            if response.status_code == requests.codes.no_content:
                logger.debug(
                    "<{}> {} {}".format(response.status_code, self.host, response.text)
                )
                return True
            else:
                logger.error(
                    "<{}> {} {}".format(response.status_code, self.host, response.text)
                )
                return False
        else:
            logger.warning("token not set")
            return False

    def getToken(self):

        try:
            url = "https://{}/auth/login".format(self.host)
            payload = {"password": self.password, "username": self.username}
            response = requests.post(
                url, data=json.dumps(payload), headers=self.http_headers, verify=False
            )
        except Exception as e:
            logger.error("SOME ERROR 2, {}".format(getattr(e, "message", repr(e))))

        if response.status_code == requests.codes.ok:
            logger.info("Successfully login to {}".format(self.host))
            logger.debug(
                "<{}> {} {}".format(response.status_code, self.host, response.text)
            )
            return response.json()["auth_token"]
        else:
            logger.error(
                "<{}> {} {}".format(response.status_code, self.host, response.text)
            )
            return None

    def logData(self, data):

        if self.es_user != "null":
            self.handler = CMRESHandler(
                hosts=[{"host": str(self.es_host), "port": int(self.es_port)}],
                auth_type=CMRESHandler.AuthType.BASIC_AUTH,
                use_ssl=True,
                verify_ssl=False,
                auth_details=(self.es_user, self.es_pwd),
                es_index_name="dockeree",
                es_additional_fields=data,
            )
        else:
            self.handler = CMRESHandler(
                hosts=[{"host": str(self.es_host), "port": int(self.es_port)}],
                auth_type=CMRESHandler.AuthType.NO_AUTH,
                es_index_name="dockeree",
                es_additional_fields=data,
            )

        # log that data
        self.eslog.addHandler(self.handler)
        self.eslog.debug(
            "[{}] Logging namespace {} quota to {}:{}".format(
                time.time(), data["metadata"]["namespace"], self.es_host, self.es_port
            )
        )
        self.eslog.removeHandler(self.handler)

    def getUnschedulableNodes(self):

        unschedulable_nodes = {}

        try:
            url = "https://{}/api/v1/nodes".format(self.host)
            response = requests.get(url, headers=self.http_headers, verify=False)
        except Exception as e:
            logger.error(
                "ERROR querying api/v1/nodes, {}".format(getattr(e, "message", repr(e)))
            )

        logger.debug(
            "<{}> {} {}".format(response.status_code, self.host, response.text)
        )

        if response.status_code != requests.codes.ok:
            logger.error(
                "<{}> {} {}".format(response.status_code, self.host, response.text)
            )
            return {}

        try:
            for node in response.json()["items"]:
                if "taints" in node["spec"]:
                    for taint in node["spec"]["taints"]:
                        if (
                            taint["key"] == "node.kubernetes.io/unschedulable"
                            and taint["effect"] == "NoSchedule"
                        ):
                            unschedulable_nodes[node["metadata"]["name"]] = taint[
                                "effect"
                            ]
        except Exception as e:
            logger.error(
                "ERROR parsing api/v1/nodes response, {}".format(
                    getattr(e, "message", repr(e))
                )
            )
            return {}

        return unschedulable_nodes

    def getKubernetesWorkerResources(self):

        result = {"node": {}, "total": {}, "unit": {"memory": "bytes", "cpu": "nano"}}
        totalCPU = 0
        totalMEM = 0

        unschedulable_nodes = self.getUnschedulableNodes()

        try:
            url = "https://{}/nodes?filters=%7B%22role%22%3A%5B%22worker%22%5D%7D".format(
                self.host
            )
            response = requests.get(url, headers=self.http_headers, verify=False)
        except Exception as e:
            logger.error("SOME ERROR 3, {}".format(getattr(e, "message", repr(e))))

        logger.debug(
            "<{}> {} {}".format(response.status_code, self.host, response.text)
        )

        if response.status_code == requests.codes.ok:
            try:
                for x in response.json():

                    # Ignore any drained nodes when calculating how much resources are available
                    if x["Description"]["Hostname"] in unschedulable_nodes:
                        logger.info(
                            "skipping unschedulable node {}".format(
                                x["Description"]["Hostname"]
                            )
                        )
                        continue

                    if (
                        x["Spec"]["Labels"]["com.docker.ucp.collection"] == "shared"
                        and x["Spec"]["Labels"][
                            "com.docker.ucp.orchestrator.kubernetes"
                        ]
                        == "true"
                        and x["Spec"]["Availability"] == "active"
                        and x["Status"]["State"] == "ready"
                    ):
                        totalCPU = totalCPU + x["Description"]["Resources"]["NanoCPUs"]
                        totalMEM = (
                            totalMEM + x["Description"]["Resources"]["MemoryBytes"]
                        )
                        result["node"][x["Description"]["Hostname"]] = {
                            "cpu": x["Description"]["Resources"]["NanoCPUs"],
                            "memory": x["Description"]["Resources"]["MemoryBytes"],
                        }

                result["total"] = {"memory": totalMEM, "cpu": totalCPU}
            except Exception as e:
                logger.error("SOME ERROR 4, {}".format(getattr(e, "message", repr(e))))

            logger.debug("{}".format(json.dumps(result)))

            return result

        else:
            logger.error(
                "<{}> {} {}".format(response.status_code, self.host, response.text)
            )
            return None

    def getKubernetesNamespaceResourceQuota(self):

        try:
            url = "https://{}/api/v1/resourcequotas".format(self.host)
            response = requests.get(url, headers=self.http_headers, verify=False)
        except Exception as e:
            logger.error("SOME ERROR 5, {}".format(getattr(e, "message", repr(e))))

        logger.debug(
            "<{}> {} {}".format(response.status_code, self.host, response.text)
        )

        # TEMPLATE = { "metadata": { "namespace": "NULL", "type": "ResourceQuota", "scope":"namespace" }, "quota": { "utilization": { "memory": 0, "cpu": 0 }, "hard": { "cpu": 0, "memory": 0 }, "used": { "cpu": 0, "memory": 0 }, "unit": { "memory": "mebibyte", "cpu": "millicore" } } }

        if response.status_code == requests.codes.ok:

            total = {
                "metadata": {
                    "namespace": "NULL",
                    "type": "ResourceQuota",
                    "scope": "namespace",
                },
                "quota": {
                    "utilization": {"memory": 0, "cpu": 0},
                    "hard": {"cpu": 0, "memory": 0},
                    "used": {"cpu": 0, "memory": 0},
                    "unit": {"memory": "byte", "cpu": "millicore"},
                },
            }
            cluster = {
                "metadata": {
                    "namespace": "NULL",
                    "type": "ResourceQuota",
                    "scope": "namespace",
                },
                "quota": {
                    "utilization": {"memory": 0, "cpu": 0},
                    "hard": {"cpu": 0, "memory": 0},
                    "used": {"cpu": 0, "memory": 0},
                    "unit": {"memory": "byte", "cpu": "millicore"},
                },
            }

            for x in response.json()["items"]:

                try:
                    if x["metadata"]["namespace"]:

                        # Reset data variable
                        data = {
                            "metadata": {
                                "namespace": "NULL",
                                "type": "ResourceQuota",
                                "scope": "namespace",
                            },
                            "quota": {
                                "utilization": {"memory": 0, "cpu": 0},
                                "hard": {"cpu": 0, "memory": 0},
                                "used": {"cpu": 0, "memory": 0},
                                "unit": {"memory": "mebibyte", "cpu": "millicore"},
                            },
                        }
                        # Namespace
                        data["metadata"]["namespace"] = x["metadata"]["namespace"]
                        # CPU LIMITS
                        data["quota"]["hard"]["cpu"] = int(
                            "".join(
                                re.findall(r"\d+", x["status"]["hard"]["limits.cpu"])
                            )
                        )
                        unit_limits_cpu = "".join(
                            re.findall(r"\D+", x["status"]["hard"]["limits.cpu"])
                        )
                        # CPU USAGE
                        data["quota"]["used"]["cpu"] = int(
                            "".join(
                                re.findall(r"\d+", x["status"]["used"]["limits.cpu"])
                            )
                        )
                        unit_used_cpu = "".join(
                            re.findall(r"\D+", x["status"]["used"]["limits.cpu"])
                        )
                        # MEMORY LIMITS
                        data["quota"]["hard"]["memory"] = int(
                            "".join(
                                re.findall(r"\d+", x["status"]["hard"]["limits.memory"])
                            )
                        )
                        unit_limits_memory = "".join(
                            re.findall(r"\D+", x["status"]["hard"]["limits.memory"])
                        )
                        # MEMORY USAGE
                        data["quota"]["used"]["memory"] = int(
                            "".join(
                                re.findall(r"\d+", x["status"]["used"]["limits.memory"])
                            )
                        )
                        unit_used_memory = "".join(
                            re.findall(r"\D+", x["status"]["used"]["limits.memory"])
                        )
                        # Make sure cpu is in unit millicore
                        if data["quota"]["hard"]["cpu"] > 0 and unit_limits_cpu == "":
                            data["quota"]["hard"]["cpu"] = (
                                data["quota"]["hard"]["cpu"] * 1000
                            )

                        if data["quota"]["used"]["cpu"] > 0 and unit_used_cpu == "":
                            data["quota"]["used"]["cpu"] = (
                                data["quota"]["used"]["cpu"] * 1000
                            )

                        # Units when normalize memory to bytes
                        memory_units = {
                            "Ti": 1024 ** 4,
                            "Gi": 1024 ** 3,
                            "Mi": 1024 ** 2,
                            "Ki": 1024,
                            "T": 1000 ** 4,
                            "G": 1000 ** 3,
                            "M": 1000 ** 2,
                            "K": 1000,
                        }

                        # If string is "empty" we know values already is in the unit byte
                        if unit_limits_memory != "":
                            try:
                                data["quota"]["hard"]["memory"] = (
                                    data["quota"]["hard"]["memory"]
                                    * memory_units[unit_limits_memory]
                                )
                            except KeyError:
                                logger.error(
                                    "SCRIPT-ERROR;Unknown unit ({}) for memory limit in namespace {}".format(
                                        unit_limits_memory,
                                        data["metadata"]["namespace"],
                                    )
                                )

                        if unit_used_memory != "":
                            try:
                                data["quota"]["used"]["memory"] = (
                                    data["quota"]["used"]["memory"]
                                    * memory_units[unit_used_memory]
                                )
                            except KeyError:
                                logger.error(
                                    "SCRIPT-ERROR;Unknown unit ({}) for memory used in namespace {}".format(
                                        unit_used_memory, data["metadata"]["namespace"]
                                    )
                                )

                        # calculate utilization
                        data["quota"]["utilization"]["cpu"] = round(
                            float(
                                float(data["quota"]["used"]["cpu"])
                                / float(data["quota"]["hard"]["cpu"])
                            )
                            * 100,
                            1,
                        )
                        data["quota"]["utilization"]["memory"] = round(
                            float(
                                float(data["quota"]["used"]["memory"])
                                / float(data["quota"]["hard"]["memory"])
                            )
                            * 100,
                            1,
                        )

                        # Add to total
                        total["quota"]["hard"]["cpu"] = (
                            total["quota"]["hard"]["cpu"] + data["quota"]["hard"]["cpu"]
                        )
                        total["quota"]["used"]["cpu"] = (
                            total["quota"]["used"]["cpu"] + data["quota"]["used"]["cpu"]
                        )
                        total["quota"]["hard"]["memory"] = (
                            total["quota"]["hard"]["memory"]
                            + data["quota"]["hard"]["memory"]
                        )
                        total["quota"]["used"]["memory"] = (
                            total["quota"]["used"]["memory"]
                            + data["quota"]["used"]["memory"]
                        )
                        # send data to elastic
                        self.logData(data)
                        logger.debug("DATA2\n{}".format(json.dumps(data, indent=4)))

                except Exception as e:
                    logger.error(
                        "SOME ERROR 6, {}".format(getattr(e, "message", repr(e)))
                    )
            try:
                # calculate total utilization
                total["quota"]["utilization"]["cpu"] = round(
                    float(
                        float(total["quota"]["used"]["cpu"])
                        / float(total["quota"]["hard"]["cpu"])
                    )
                    * 100,
                    1,
                )
                total["quota"]["utilization"]["memory"] = round(
                    float(
                        float(total["quota"]["used"]["memory"])
                        / float(total["quota"]["hard"]["memory"])
                    )
                    * 100,
                    1,
                )
                logger.debug("TOTAL2\n{}".format(json.dumps(total, indent=4)))
                self.logData(total)
            except Exception as e:
                logger.error("SOME ERROR 7, {}".format(getattr(e, "message", repr(e))))
            try:
                # calculate cluster utilization

                logger.debug("CLUSTER1\n{}".format(json.dumps(cluster, indent=4)))

                cluster_nodes = self.getKubernetesWorkerResources()
                cluster["metadata"]["scope"] = "cluster"

                cluster["quota"]["hard"]["cpu"] = float(
                    cluster_nodes["total"]["cpu"] / 1000000
                )
                cluster["quota"]["used"]["cpu"] = total["quota"]["hard"]["cpu"]

                cluster["quota"]["hard"]["memory"] = float(
                    cluster_nodes["total"]["memory"]
                )
                cluster["quota"]["used"]["memory"] = total["quota"]["hard"]["memory"]

                cluster["quota"]["utilization"]["cpu"] = round(
                    float(
                        float(cluster["quota"]["used"]["cpu"])
                        / float(cluster["quota"]["hard"]["cpu"])
                    )
                    * 100,
                    1,
                )
                cluster["quota"]["utilization"]["memory"] = round(
                    float(
                        float(cluster["quota"]["used"]["memory"])
                        / float(cluster["quota"]["hard"]["memory"])
                    )
                    * 100,
                    1,
                )

                logger.debug("CLUSTER2\n{}".format(json.dumps(cluster, indent=4)))
                self.logData(cluster)
            except Exception as e:
                logger.error("SOME ERROR 8, {}".format(getattr(e, "message", repr(e))))

            return True

        else:
            logger.error(
                "<{}> {} {}".format(response.status_code, self.host, response.text)
            )
            return False


if __name__ == "__main__":

    # collection interval
    SLEEP = 30
    try:
        # Get all the environment data
        DOCKEREE_USERNAME = os.environ[r"DOCKEREE_USERNAME"].rstrip("\n\r")
        DOCKEREE_PASSWORD = os.environ[r"DOCKEREE_PASSWORD"].rstrip("\n\r")
        DOCKEREE_HOST = os.environ[r"DOCKEREE_HOST"].rstrip("\n\r")
        ELASTIC_USERNAME = os.environ[r"ELASTIC_USERNAME"].rstrip("\n\r")
        ELASTIC_PASSWORD = os.environ[r"ELASTIC_PASSWORD"].rstrip("\n\r")
        ELASTIC_HOST = os.environ[r"ELASTIC_HOST"].rstrip("\n\r")
        ELASTIC_PORT = os.environ[r"ELASTIC_PORT"].rstrip("\n\r")
    except Exception as error:
        logger.error(
            "Problem picking up all the environment variables, {}".format(error)
        )
        sys.exit(1)
    try:
        # Connect to ucp
        ucp = DockerEE(
            DOCKEREE_HOST,
            DOCKEREE_USERNAME,
            DOCKEREE_PASSWORD,
            ELASTIC_HOST,
            ELASTIC_PORT,
            ELASTIC_USERNAME,
            ELASTIC_PASSWORD,
        )
    except Exception as error:
        logger.error("Failure to init DockerEE class, {}".format(error))

    logger.info(
        "Start collecting data from '{}' and send to '{}'".format(
            DOCKEREE_HOST, ELASTIC_HOST
        )
    )

    # Loop until further notice...
    while True:
        try:
            # collect, calculate & log quota data
            try:
                ucp.getKubernetesNamespaceResourceQuota()
                logger.info("Sleep for {} seconds".format(SLEEP))
            except Exception as error:
                logger.error(error)
                raise RuntimeError
        except Exception as error:
            logging.error("Total failure, {}".format(error))
            sys.exit(1)
        # sleep for a while...
        time.sleep(SLEEP)

# j0nix 2019
