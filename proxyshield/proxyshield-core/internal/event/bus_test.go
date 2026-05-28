package event_test

import (
	"testing"

	"github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/event"
)

func TestBusDeliversToNamedSubscriber(t *testing.T) {
	bus := event.NewBus(4)
	ch := bus.Subscribe(event.RequestBlocked)
	bus.Publish(event.Event{Name: event.RequestBlocked})
	select {
	case e := <-ch:
		if e.Name != event.RequestBlocked {
			t.Fatalf("got event %q", e.Name)
		}
	default:
		t.Fatal("expected the named subscriber to receive the event")
	}
}

func TestBusSubscribeAllReceivesEverything(t *testing.T) {
	bus := event.NewBus(4)
	all := bus.SubscribeAll()
	bus.Publish(event.Event{Name: event.CacheHit})
	select {
	case <-all:
	default:
		t.Fatal("SubscribeAll should receive every event")
	}
}

func TestBusDoesNotDeliverUnrelatedEvents(t *testing.T) {
	bus := event.NewBus(4)
	ch := bus.Subscribe(event.RequestBlocked)
	bus.Publish(event.Event{Name: event.RequestForwarded})
	select {
	case <-ch:
		t.Fatal("subscriber should not receive an unrelated event")
	default:
	}
}

func TestBusDropsWhenBufferFull(t *testing.T) {
	bus := event.NewBus(1)
	ch := bus.Subscribe("x")
	bus.Publish(event.Event{Name: "x"})
	bus.Publish(event.Event{Name: "x"}) // buffer full → dropped, must not block
	<-ch
	select {
	case <-ch:
		t.Fatal("the second event should have been dropped, not buffered")
	default:
	}
}

func TestBusUnsubscribe(t *testing.T) {
	bus := event.NewBus(4)
	ch := bus.Subscribe("x")
	bus.Unsubscribe("x", ch)
	bus.Publish(event.Event{Name: "x"})
	select {
	case <-ch:
		t.Fatal("an unsubscribed channel must not receive events")
	default:
	}
}
