package server

import (
	"context"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/network"
)

// Private networking

func (s serverService) GetNetwork(ctx context.Context, _ *agentv1.GetNetworkRequest) (*agentv1.GetNetworkResponse, error) {
	status, err := s.Network.Status(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetNetworkResponse{Address: status.Address, Revision: status.Revision, FirewallActive: status.FirewallActive, BroadRules: status.BroadRules}
	for _, peer := range status.Peers {
		response.Peers = append(response.Peers, &agentv1.NetworkPeer{Id: peer.ID, Name: peer.Name, Address: peer.Address})
	}
	for _, candidate := range status.Candidates {
		response.Candidates = append(response.Candidates, &agentv1.NetworkAddress{Address: candidate.Address, Interface: candidate.Interface})
	}
	for _, service := range status.Services {
		response.Services = append(response.Services, &agentv1.NetworkService{Name: service.Name, Port: uint32(service.Port)})
	}

	return response, nil
}

func (s serverService) PutNetwork(ctx context.Context, request *agentv1.PutNetworkRequest) (*agentv1.PutNetworkResponse, error) {
	peers := make([]network.Peer, 0, len(request.Peers))
	for _, peer := range request.Peers {
		peers = append(peers, network.Peer{ID: peer.Id, Name: peer.Name, Address: peer.Address})
	}

	revision, err := s.Network.Put(ctx, request.Address, peers, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutNetworkResponse{Revision: revision}, nil
}

func (s serverService) CheckConnection(ctx context.Context, request *agentv1.CheckConnectionRequest) (*agentv1.CheckConnectionResponse, error) {
	result, detail, err := network.Check(ctx, request.Address, int(request.Port))
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.CheckConnectionResponse{Result: result, Detail: detail}, nil
}
