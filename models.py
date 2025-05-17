from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class NatRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table = db.Column(db.String(10), default='nat', nullable=False)
    chain = db.Column(db.String(20), nullable=False)
    protocol = db.Column(db.String(10))
    source = db.Column(db.String(50))
    destination = db.Column(db.String(50))
    in_interface = db.Column(db.String(16))
    out_interface = db.Column(db.String(16))
    source_port = db.Column(db.String(10))
    destination_port = db.Column(db.String(10))
    target = db.Column(db.String(20), nullable=False)
    to_destination = db.Column(db.String(50))
    to_source = db.Column(db.String(50))
    description = db.Column(db.String(255))

    def build_iptables_command_add(self):
        cmd = [
            'iptables',
            '-t', self.table,
            '-A', self.chain,
        ]

        if self.protocol:
            cmd.extend(['-p', self.protocol])
        if self.source:
            cmd.extend(['-s', self.source])
        if self.destination:
            cmd.extend(['-d', self.destination])
        if self.in_interface:
            cmd.extend(['-i', self.in_interface])
        if self.out_interface:
            cmd.extend(['-o', self.out_interface])

        if self.protocol and self.protocol != 'all':
            if self.source_port:
                 cmd.extend(['--sport', self.source_port])
            if self.destination_port:
                 cmd.extend(['--dport', self.destination_port])

        cmd.extend(['-j', self.target])

        if self.target == 'DNAT' and self.to_destination:
            cmd.extend(['--to-destination', self.to_destination])
        elif self.target == 'SNAT' and self.to_source:
            cmd.extend(['--to-source', self.to_source])

        return cmd

    def build_iptables_command_delete(self):
        cmd = self.build_iptables_command_add()
        cmd[cmd.index('-A')] = '-D'
        return cmd
