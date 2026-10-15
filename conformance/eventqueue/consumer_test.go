package eventqueue

import "testing"

func TestConsumerSerializesFourChannelsWithoutCompletingPublishers(t *testing.T) {
	d, m := driver{t}, New()
	ids := []string{"events", "timeout", "committed", "retry"}
	c, err := NewConsumer(ids...)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		d.ok(m.Subscribe(id, stamp(0), id))
		d.ok(m.Call(Event{ID: "post-" + id, Kind: id, Stamp: stamp(1)}))
		d.ok(m.Snapshot("post-" + id))
		d.ok(m.Enter("post-" + id))
	}
	for i, id := range ids {
		post := "post-" + id
		d.ok(c.Receive(m, post))
		if c.Active() != post {
			t.Fatal(c.Active())
		}
		if i+1 < len(ids) {
			d.blocked(c.Receive(m, "post-"+ids[i+1]))
		}
		d.ok(c.Finish())
		p, _ := m.Post(post)
		if p.Phase != Releasing {
			t.Fatal("handler completion released the publisher", p)
		}
	}
	// All handlers finished while all publishers still own their read locks.
	for _, id := range ids {
		d.ok(m.Release("post-" + id))
		d.ok(m.Return("post-" + id))
	}
}

func TestConsumerMayFinishAfterPublisherReturnedAndCloseIsReady(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("sub", stamp(0), "request"))
	c, _ := NewConsumer("sub")
	d.ok(m.Call(Event{ID: "post", Kind: "request", Stamp: stamp(1)}))
	d.ok(m.Snapshot("post"))
	d.ok(m.Enter("post"))
	d.ok(c.Receive(m, "post"))
	d.ok(m.Release("post"))
	d.ok(m.Return("post"))
	d.ok(m.Remove("sub"))
	d.ok(m.SignalClose("sub"))
	d.ok(m.BeginJoin("sub"))
	d.ok(m.FinishClose("sub"))
	d.blocked(c.Exit(m, "sub"))
	if c.Active() != "post" {
		t.Fatal("channel close interrupted active handling")
	}
	d.ok(c.Finish())
	d.ok(c.Exit(m, "sub"))
	if !c.Exited() {
		t.Fatal("closed receive did not exit")
	}
	d.invalid(c.Receive(m, "post"))
}

func TestConsumerChoosesEitherClosedChannelOrAnotherReadyDelivery(t *testing.T) {
	for _, receive := range []bool{false, true} {
		d, m := driver{t}, New()
		for _, id := range []string{"closed", "ready"} {
			d.ok(m.Subscribe(id, stamp(0), id))
		}
		c, _ := NewConsumer("closed", "ready")
		d.ok(m.Remove("closed"))
		d.ok(m.SignalClose("closed"))
		d.ok(m.BeginJoin("closed"))
		d.ok(m.FinishClose("closed"))
		d.ok(m.Call(Event{ID: "post", Kind: "ready", Stamp: stamp(1)}))
		d.ok(m.Snapshot("post"))
		d.ok(m.Enter("post"))
		if receive {
			d.ok(c.Receive(m, "post"))
			d.ok(c.Finish())
		}
		d.ok(c.Exit(m, "closed"))
		p, _ := m.Post("post")
		want := Delivering
		if receive {
			want = Releasing
		}
		if p.Phase != want {
			t.Fatal("exit invented a publisher outcome", p)
		}
	}
}

func TestConsumerDoesNotReadAnUnregisteredChannel(t *testing.T) {
	d, m := driver{t}, New()
	d.ok(m.Subscribe("other", stamp(0), "message"))
	d.ok(m.Call(Event{ID: "post", Kind: "message", Stamp: stamp(1)}))
	d.ok(m.Snapshot("post"))
	d.ok(m.Enter("post"))
	c, _ := NewConsumer("mine")
	d.invalid(c.Receive(m, "post"))
	p, _ := m.Post("post")
	if p.Phase != Delivering || c.Active() != "" {
		t.Fatal("invalid receive changed state", p)
	}
	if _, err := NewConsumer("same", "same"); err == nil {
		t.Fatal("duplicate channels accepted")
	}
}
