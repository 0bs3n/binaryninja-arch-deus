from binaryninja import Architecture, BinaryReader, BinaryView
from binaryninja.enums import SectionSemantics, SegmentFlag


class DeusView(BinaryView):
    """
    This is our custom Binary View.
    """
    name = 'DEUS File'

    @classmethod
    def is_valid_for_data(cls, data):
        """
        This function tells Binja whether to use this view for a given file
        """
        if data[0:4] == b'DEUS':
            return True
        return False

    def __init__(self, data):
        """
        Once our view is selected, this method is called to actually create it.
        :param data: the file data
        """
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.platform = Architecture['deus'].standalone_platform

        self.parse_format(data)

    def parse_format(self, data):
        """
        This is a helper function to parse our BS format
        :param data:
        :return:
        """
        reader = BinaryReader(data)
        reader.seek(4)
        mem_size = reader.read32()
        loading_addr = mem_size
        data_addr = 0
        header_len = 8
        code_len = len(data) - header_len
        code_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
        data_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable

        self.add_auto_segment(loading_addr, code_len, header_len, code_len, code_flags)
        self.add_auto_section("text", loading_addr, code_len,
                              SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_auto_segment(data_addr, mem_size, 0, 0, data_flags)
        self.add_auto_section("data", data_addr, mem_size,
                              SectionSemantics.ReadWriteDataSectionSemantics)

        self.add_entry_point(loading_addr)
