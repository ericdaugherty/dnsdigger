package dnsdigger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestQueryZone(t *testing.T) {
	ctx := context.Background()
	domain := "ericdaugherty.com"

	z, err := Query(ctx, domain)
	require.NoError(t, err, "Error Querying zone")

	assert.Equal(t, domain, z.Name)
	require.Len(t, z.A, 1)
	assert.Equal(t, "34.194.118.33", z.A[0].Addr)
	require.Len(t, z.A[0].Ptrs, 1)
	assert.Equal(t, "ec2-34-194-118-33.compute-1.amazonaws.com", z.A[0].Ptrs[0])
	assert.Equal(t, "Amazon.com, Inc.", z.A[0].Owner)

	// MX
	mx := z.MX
	assert.Len(t, mx, 5)
	assert.Equal(t, uint16(0), mx[0].Priority)
	assert.Equal(t, uint16(5), mx[1].Priority)
	assert.Equal(t, uint16(5), mx[2].Priority)
	assert.Equal(t, uint16(10), mx[3].Priority)
	assert.Equal(t, uint16(10), mx[4].Priority)
	assert.Equal(t, mx[0].Host.Name, "aspmx.l.google.com")

	// NS
	ns := z.NS
	assert.Len(t, ns, 2)
	assert.Equal(t, "ns11.domaincontrol.com", ns[0].Name)
	assert.Len(t, ns[0].IPs, 2)
}

func TestGetOwner(t *testing.T) {

	name := "ec2-34-194-118-33.compute-1.amazonaws.com"
	owner := getOwner(name)
	assert.Equal(t, "Amazon.com, Inc.", owner)

	name = "yx-in-f26.1e100.net"
	owner = getOwner(name)
	assert.Equal(t, "Google LLC", owner)
}
