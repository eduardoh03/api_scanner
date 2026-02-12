import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_scan_unauthenticated(client: AsyncClient):
    response = await client.post("/scans", json={"target": "example.com"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_scans_unauthenticated(client: AsyncClient):
    response = await client.get("/scans")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_scans_empty(authenticated_client: AsyncClient):
    response = await authenticated_client.get("/scans")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_get_scan_not_found(authenticated_client: AsyncClient):
    response = await authenticated_client.get("/scans/nonexistent-id")
    assert response.status_code == 404
