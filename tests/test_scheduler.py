from concurrent.futures import ThreadPoolExecutor
import pytest
from shadow_hunter.scheduler import DurableScheduler, QueueBusy
from shadow_hunter.store import SQLiteStore
from shadow_hunter.policy import Principal, PolicyEngine
from shadow_hunter.gateway import ToolGateway
from shadow_hunter.approvals import ApprovalService

@pytest.fixture
def context(tmp_path):
    store = SQLiteStore(tmp_path / "jobs.sqlite")
    a = Principal("a","t","c",True)
    b = Principal("b","other","other",True)
    store.add_order(order_id="owned",tenant_id="t",customer_id="c",currency="USD",refundable_minor=1000)
    return store,a,b,ToolGateway(store,PolicyEngine(),ApprovalService(store,ttl_seconds=60))

def test_persistence_dispatch_and_gateway(context):
    store,a,b,gateway = context
    job = DurableScheduler(store).enqueue(a,"order_and_refund_review","owned")
    queue = DurableScheduler(SQLiteStore(store.database_path))
    assert queue.list(b)==[]
    assert queue.dispatch_next(b,gateway) is None
    assert not queue.cancel(b,job)
    result = queue.dispatch_next(a,gateway)
    assert result["status"]=="completed"
    assert result["result"]["verified_steps"]==2
    assert queue.list(a)[0]["state"]=="completed"
    assert queue.dispatch_next(a,gateway) is None

def test_foreign_resource_denied(context):
    store,a,b,gateway = context
    queue=DurableScheduler(store)
    queue.enqueue(b,"order_and_refund_review","owned")
    result=queue.dispatch_next(b,gateway)
    assert result["status"]=="denied"
    assert result["result"]["verified_steps"]==1
    assert "order" not in result["result"]["steps"][0]["result"]

def test_atomic_claims_and_expiration(context, monkeypatch):
    store,a,b,gateway=context
    queue=DurableScheduler(store)
    job=queue.enqueue(a,"order_summary","owned")
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims=list(pool.map(lambda _:queue.claim_next(a),range(4)))
    assert sum(c is not None for c in claims)==1
    entry,claim=next(c for c in claims if c is not None)
    assert not queue.finish(b,job,claim,"completed",None)
    assert not queue.finish(a,job,"wrong","completed",None)
    with store._transaction() as conn:
        conn.execute("UPDATE local_jobs SET lease=0 WHERE job_id=?",(job,))
    assert queue.list(a)[0]["state"]=="interrupted"
    assert not queue.finish(a,job,claim,"completed",None)
    assert queue.claim_next(a) is None

def test_capacity_and_cancel(context):
    store,a,b,gateway=context
    queue=DurableScheduler(store)
    with pytest.raises(ValueError):
        queue.enqueue(a,"create_refund_request","owned")
    ids=[queue.enqueue(a,"refund_status","owned") for _ in range(8)]
    with pytest.raises(QueueBusy):
        queue.enqueue(a,"refund_status","owned")
    assert queue.cancel(a,ids[0])
    assert not queue.cancel(a,ids[0])
    queue.enqueue(a,"refund_status","owned")

def test_authenticated_http_queue(context,monkeypatch):
    from fastapi.testclient import TestClient
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter.api import create_app
    store,a,b,gateway=context
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"a":{"subject_id":"a","tenant_id":"t","customer_id":"c"},
        "b":{"subject_id":"b","tenant_id":"other","customer_id":"other"}},operator_tokens={})
    client=TestClient(create_app(store=store,authenticator=auth))
    path="/v1/agent/local-jobs"
    ha={"Authorization":"Bearer a"}; hb={"Authorization":"Bearer b"}
    assert client.get(path).status_code==401
    assert client.post(path,headers=ha,json={"capability":"write","order_id":"owned"}).status_code==422
    res=client.post(path,headers=ha,json={"capability":"order_summary","order_id":"owned"})
    assert res.status_code==200
    job=res.json()["job_id"]
    assert client.post(path+"/"+job+"/cancel",headers=hb).status_code==404
    assert client.get(path,headers=hb).json()["jobs"]==[]
    assert client.post(path+"/run-next",headers=hb).json()["status"]=="empty"
    assert client.post(path+"/run-next",headers=ha).json()["status"]=="completed"


def test_independent_batch_dispatch(context):
    store,a,b,gateway=context
    queue=DurableScheduler(store)
    ids={queue.enqueue(a,cap,"owned") for cap in ("order_summary","refund_status","order_and_refund_review")}
    queue.enqueue(b,"order_summary","owned")
    results=queue.dispatch_batch(a,gateway)
    assert {r["job_id"] for r in results}==ids
    assert all(r["status"]=="completed" for r in results)
    assert len({r["trace_id"] for r in results})==3
    assert queue.list(b)[0]["state"]=="queued"


def test_utility_registry_without_business_gateway(context):
    store,a,b,gateway=context
    queue=DurableScheduler(store)
    queue.enqueue(a,"numeric_summary","1,2.5,-1")
    result=queue.dispatch_next(a,None)
    assert result["status"]=="completed" and result["result"]["sum"]=="2.5"
    with pytest.raises(ValueError):
        queue.enqueue(a,"numeric_summary","1,invalid")
    with pytest.raises(ValueError):
        queue.enqueue(a,"model_readiness","http://example.com")


def test_scheduled_jobs_wait_and_revalidate(context,monkeypatch):
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter import scheduler as module
    store,a,b,gateway=context
    queue=DurableScheduler(store)
    now=100000
    monkeypatch.setattr(module.time,"time",lambda:now)
    first=queue.enqueue(a,"order_summary","owned",delay_seconds=60)
    second=queue.enqueue(b,"order_summary","owned",delay_seconds=60)
    auth=TokenAuthenticator(customer_tokens={"a":{"subject_id":"a","tenant_id":"t","customer_id":"c"}},operator_tokens={})
    assert queue.claim_next(a) is None
    assert queue.dispatch_due(gateway,auth.resolve_scheduled_owner)==[]
    now+=60
    results=queue.dispatch_due(gateway,auth.resolve_scheduled_owner)
    assert len(results)==1 and results[0]["status"]=="completed"
    assert queue.list(a)[0]["state"]=="completed"
    assert queue.list(b)[0]["state"]=="denied"
    assert queue.dispatch_due(gateway,auth.resolve_scheduled_owner)==[]


def test_scheduled_expiry_cancel_and_restart(context,monkeypatch):
    from shadow_hunter import scheduler as module
    store,a,b,gateway=context
    now=100000
    monkeypatch.setattr(module.time,"time",lambda:now)
    queue=DurableScheduler(store)
    job=queue.enqueue(a,"numeric_summary","1,2",delay_seconds=20)
    other=queue.enqueue(a,"numeric_summary","1,2",delay_seconds=20)
    assert queue.cancel(a,other)
    queue=DurableScheduler(SQLiteStore(store.database_path))
    now+=321
    assert queue.dispatch_due(gateway,lambda owner:a)==[]
    assert {r["job_id"]:r["state"] for r in queue.list(a)}=={job:"interrupted",other:"cancelled"}


def test_unattended_worker_lifespan(context,monkeypatch):
    import time
    from fastapi.testclient import TestClient
    from shadow_hunter.auth import TokenAuthenticator
    from shadow_hunter.api import create_app
    store,a,b,gateway=context
    monkeypatch.setenv("SHADOW_HUNTER_AUTH_MODE","local")
    monkeypatch.setenv("SHADOW_HUNTER_LOCAL_READONLY_ENABLED","true")
    monkeypatch.setenv("SHADOW_HUNTER_AUTO_JOBS_ENABLED","true")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME",raising=False)
    auth=TokenAuthenticator(customer_tokens={"a":{"subject_id":"a","tenant_id":"t","customer_id":"c"}},operator_tokens={})
    path="/v1/agent/local-jobs"; headers={"Authorization":"Bearer a"}
    with TestClient(create_app(store=store,authenticator=auth)) as client:
        response=client.post(path,headers=headers,json={"capability":"numeric_summary","order_id":"1,2,3","delay_seconds":0})
        assert response.status_code==200
        for _ in range(30):
            rows=client.get(path,headers=headers).json()["jobs"]
            if rows and rows[0]["state"]=="completed": break
            time.sleep(.1)
        assert rows[0]["state"]=="completed"
        assert client.post(path,headers=headers,json={"capability":"numeric_summary","order_id":"1,2","delay_seconds":3601}).status_code==422
        monkeypatch.setenv("SHADOW_HUNTER_AUTO_JOBS_ENABLED","false")
        assert client.post(path,headers=headers,json={"capability":"numeric_summary","order_id":"1,2","delay_seconds":0}).status_code==422
