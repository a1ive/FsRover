/* Indexed ReFS lookup, extent reads and compression-table regression probes. */
#define main refs_review_main
#include "refs_review_probe.c"
#undef main

static unsigned failures;
#define CHECK(expr) do { checks++; if (!(expr)) { failures++; fprintf(stderr, "FAIL line %u: %s (%s)\n", __LINE__, #expr, grub_errmsg); } } while (0)

static void put16(unsigned char *p, unsigned n)
{
	grub_uint16_t value = grub_cpu_to_le16((grub_uint16_t) n);
	memcpy(p, &value, 2);
}

static unsigned char *
start_table(unsigned block, int index, unsigned count)
{
	unsigned char *p, *t;
	node(block, "MSB+", 0, 0);
	p = media + block * block_size;
	put32(p + 0x50, 4);
	t = p + 0x54;
	put32(t, 0x24); t[0xD] = (unsigned char) index;
	put32(t + 0x10, 0x3000); put32(t + 0x14, count);
	put32(t + 0x20, 0x3000 + 4 * count);
	return t;
}

static void
row(unsigned char *t, unsigned i, const unsigned char *key, unsigned klen,
	const unsigned char *value, unsigned vlen)
{
	unsigned off = 0x40 + i * 256;
	unsigned char *p = t + off;
	put32(t + 0x3000 + 4 * i, off);
	put32(p, 16 + klen + vlen); put16(p + 4, 16); put16(p + 6, klen);
	put16(p + 10, 16 + klen); put16(p + 12, vlen);
	memcpy(p + 16, key, klen); memcpy(p + 16 + klen, value, vlen);
}

static unsigned
name_key(unsigned char *key, const char *name)
{
	unsigned i, n = (unsigned) strlen(name);
	memset(key, 0, 128); put16(key, REFS_KEY_DIRENT); put16(key + 2, REFS_DIRENT_LONG);
	for (i = 0; i < n; i++) put16(key + 4 + 2 * i, (unsigned char) name[i]);
	return 4 + 2 * n;
}

static void
lookup_cases(void)
{
	struct grub_refs_data d = {0}; struct grub_disk disk = {0};
	struct grub_fshelp_node dir = {0}, *found;
	enum grub_fshelp_filetype type;
	unsigned char key[128] = {0}, value[128] = {0}, *t;
	grub_uint64_t root[4]; unsigned i, before;
	const char *names[] = {"alpha", "middle", "omega", "ALPHA", "\xE4\xB8\xAD"};

	fixture(3,14,1,2);
	d.disk=&disk; d.header_size=0x50; d.table_min=0x24; d.ref_size=32;
	d.block_size=d.cluster_size=16384; d.chunk_count=1; d.cluster_shift=14;
	d.linear_limit=~(grub_uint64_t)0; d.obj_table[0]=10;
	/* Two object-map leaves; lookup of 0x600 must skip block 12. */
	t=start_table(10,1,2); put64(key+8,0x600); put64(value,11); row(t,0,key,16,value,32);
	put64(value,12); row(t,1,key,0,value,32);
	t=start_table(11,0,1); memset(value,0,sizeof(value)); put64(value+32,20); row(t,0,key,16,value,64);
	t=start_table(12,0,1); put64(key+8,0x700); put64(value+32,30); row(t,0,key,16,value,64);
	CHECK(grub_refs_find_tree(&d,0x600,root)==0 && root[0]==20 && reads[12]==0);
	CHECK(grub_refs_find_tree(&d,0x700,root)==0 && root[0]==30);
	/* Empty terminal key routes the last name to block 22. */
	t=start_table(20,1,2); memset(value,0,sizeof(value)); put64(value,21);
	row(t,0,key,name_key(key,"middle"),value,32); put64(value,22); row(t,1,key,0,value,32);
	t=start_table(21,0,2); memset(value,0,sizeof(value));
	row(t,0,key,name_key(key,"alpha"),value,96); row(t,1,key,name_key(key,"middle"),value,96);
	t=start_table(22,0,2); row(t,0,key,name_key(key,"omega"),value,96);
	name_key(key,"x"); put16(key+4,0x4E2D); row(t,1,key,6,value,96);
	dir.data=&d; dir.oid=0x600; dir.type=REFS_NODE_DIR;
	for(i=0;i<5;i++)
	{
		before=reads[21]+reads[22]; found=NULL; grub_errno=0;
		CHECK(grub_refs_lookup_file(&dir,names[i],&found,&type)==0 && found && type==GRUB_FSHELP_REG);
		if(i<4) CHECK(reads[21]+reads[22]==before+1);
		grub_free(found);
	}
	/* A differently ordered separator must not hide a matching leaf. */
	memset(key,0,sizeof(key)); put16(key,0xFFFF); memset(value,0,sizeof(value)); put64(value,21);
	t=media+20*block_size+0x54; row(t,0,key,4,value,32);
	before=reads[21]; found=NULL;
	CHECK(grub_refs_lookup_file(&dir,"omega",&found,&type)==0 && found);
	CHECK(reads[21]>=before+3);
	grub_free(found);
	row(t,0,key,name_key(key,"middle"),value,32);
	grub_errno=0;
	CHECK(grub_refs_lookup_file(&dir,"absent",&found,&type)==GRUB_ERR_FILE_NOT_FOUND);
	grub_errno=0; fail_block=22; fail_read=reads[22]+1; injected=GRUB_ERR_READ_ERROR;
	CHECK(grub_refs_lookup_file(&dir,"omega",&found,&type)==GRUB_ERR_READ_ERROR);
	fail_block=127; grub_errno=0; fail_alloc=alloc_count+1;
	CHECK(grub_refs_find_tree(&d,0x600,root)==GRUB_ERR_OUT_OF_MEMORY);
	fail_alloc=0; grub_errno=0;
	/* A branch whose child points back at itself stops after the depth limit. */
	memset(key,0,sizeof(key)); memset(value,0,sizeof(value)); put64(value,10);
	t=start_table(10,1,1); row(t,0,key,0,value,32);
	CHECK(grub_refs_find_tree(&d,0x600,root)==GRUB_ERR_BAD_FS);
	grub_errno=0;
}

static void
extent_cases(void)
{
	struct grub_refs_data d={0}; struct grub_disk disk={0};
	struct grub_fshelp_node nd={0}; struct grub_refs_stream st={0}; struct grub_file f={0};
	struct grub_refs_extent ext[64]; unsigned char expected[129*512], actual[129*512];
	unsigned i, pos, len;
	fixture(3,14,1,2); memset(expected,0,sizeof(expected));
	d.disk=&disk; d.cluster_size=512; d.cluster_shift=9;
	d.linear_limit=~(grub_uint64_t)0; d.bpc_mask=1023;
	nd.sparse=1; st.data=&d; st.node=&nd; st.ext=ext; st.ext_len=64;
	f.data=&st; f.size=sizeof(expected);
	for(i=0;i<64;i++)
	{
		ext[63-i].vcn=2*i+1; ext[63-i].count=1; ext[63-i].block=1+i;
		memset(media+(1+i)*512,(int)(32+i),512);
		memset(expected+(2*i+1)*512,(int)(32+i),512);
	}
	grub_refs_sort_extents(ext,64,NULL);
	CHECK(grub_refs_read(&f,(char *)actual,sizeof(actual))==sizeof(actual));
	CHECK(memcmp(actual,expected,sizeof(actual))==0);
	for(i=0;i<300;i++)
	{
		pos=(i*7919U)%sizeof(expected); len=1+(i*317U)%2048;
		if(len>sizeof(expected)-pos) len=sizeof(expected)-pos;
		f.offset=pos;
		CHECK(grub_refs_read(&f,(char *)actual,len)==len && memcmp(actual,expected+pos,len)==0);
	}
	f.offset=1024; CHECK(grub_refs_read(&f,(char *)actual,1)==1 && !actual[0]);
	CHECK(st.hole_start==1024 && st.hole_end==1536);
	f.offset=1535; CHECK(grub_refs_read(&f,(char *)actual,2)==2 && !actual[0] && actual[1]==33);
	nd.sparse=0; st.hole_start=st.hole_end=0; f.offset=0; grub_errno=0;
	CHECK(grub_refs_read(&f,(char *)actual,1)==-1 && grub_errno==GRUB_ERR_BAD_FS);
	grub_errno=0;
}

static void
compression_cases(void)
{
	struct grub_refs_data d={0}; struct grub_refs_map_entry map[2]={{0}};
	struct grub_refs_compression_range ranges[4]={{0}};
	grub_uint16_t ranks[2][2]={{0,8},{0,8}}; grub_uint8_t bitmaps[2]={255,255};
	struct grub_refs_map_entry *entry; grub_uint64_t physical; grub_uint32_t index;
	unsigned i;
	d.cluster_size=4096; d.cluster_shift=12; d.bpc_shift=3; d.bpc_mask=7;
	d.compression_unit_size=4096; d.compression_format=REFS_COMPRESSION_LZ4;
	d.map=map; d.map_len=2; d.compression=ranges; d.compression_len=4;
	for(i=0;i<2;i++) { map[i].id=2-i; map[i].start=128*(i+1); map[i].compact_bitmap=&bitmaps[i]; map[i].compact_rank=ranks[i]; }
	grub_refs_sort_map(map,2); d.map_sorted=1;
	CHECK(grub_refs_lookup_map(&d,16+3,&entry,&physical) && entry->id==1 && physical==259);
	CHECK(!grub_refs_lookup_map(&d,48,&entry,&physical));
	for(i=0;i<4;i++) { ranges[i].container_id=2-i/2; ranges[i].plain_start=(1-i%2)*16384; ranges[i].plain_size=16384; }
	CHECK(grub_refs_prepare_compression(&d)==0);
	CHECK(grub_refs_find_compression(&d,1,16383,&index)==&ranges[0] && index==0);
	CHECK(grub_refs_find_compression(&d,1,16384,&index)==&ranges[1] && index==1);
	CHECK(!grub_refs_find_compression(&d,1,32768,&index));
	CHECK(grub_refs_container_is_compressed(&d,2) && !grub_refs_container_is_compressed(&d,3));
	ranges[1].plain_start--; CHECK(grub_refs_prepare_compression(&d)==GRUB_ERR_BAD_FS); grub_errno=0;
	ranges[1].plain_start+=2; CHECK(grub_refs_prepare_compression(&d)==GRUB_ERR_BAD_FS); grub_errno=0;
	ranges[1].plain_start--; map[0].compact_bitmap=NULL;
	CHECK(grub_refs_prepare_compression(&d)==GRUB_ERR_BAD_FS); grub_errno=0;
	map[0].compact_bitmap=&bitmaps[0]; d.compression_unit_size=123;
	CHECK(grub_refs_prepare_compression(&d)==GRUB_ERR_BAD_FS); grub_errno=0;
}

static void
map_growth_case(void)
{
	struct grub_refs_data d={0};
	unsigned char key[8], value[0x70]={0};
	unsigned i;

	put64(value+sizeof(value)-8,8);
	for(i=0;i<1000;i++)
	{
		put64(key,1000-i);
		put64(value+sizeof(value)-16,(1000-i)*16);
		CHECK(grub_refs_map_hook(&d,0,key,sizeof(key),value,sizeof(value),NULL)==0);
	}
	CHECK(d.map_len==1000 && d.map_cap>=1000 && d.map_cap<=2048);
	grub_refs_sort_map(d.map,d.map_len);
	d.map_sorted=1;
	for(i=1;i<=1000;i++)
	{
		struct grub_refs_map_entry *entry=grub_refs_find_map(&d,i);
		CHECK(entry && entry->start==(grub_uint64_t)i*16);
	}
	grub_refs_reset_checkpoint(&d);
	CHECK(!d.map && !d.map_len && !d.map_cap && !d.map_sorted);
}

/* An insertion-sort oracle checks keys; record tags check payload preservation. */
static void
sort_cases(void)
{
	struct grub_refs_map_entry map[130], original_map[130];
	struct grub_refs_compression_range ranges[130], original_ranges[130];
	grub_uint64_t ids[130], containers[130], starts[130];
	unsigned char seen_map[130], seen_ranges[130];
	unsigned n, pattern, i, j;

	grub_refs_sort_map(NULL, 0);
	grub_refs_sort_compression(NULL, 0);
	for (n = 0; n <= 130; n++)
		for (pattern = 0; pattern < 5; pattern++)
		{
			memset(map, 0, sizeof(map));
			memset(ranges, 0, sizeof(ranges));
			memset(seen_map, 0, sizeof(seen_map));
			memset(seen_ranges, 0, sizeof(seen_ranges));
			for (i = 0; i < n; i++)
			{
				grub_uint64_t key = pattern == 0 ? i : pattern == 1 ? n - i :
					pattern == 2 ? i % 3 : pattern == 3 ? ~(grub_uint64_t) 0 :
					((grub_uint64_t) i * 2654435761U) ^ (~(grub_uint64_t) 0 - i);
				map[i].id = ids[i] = key;
				map[i].start = i;
				map[i].count = 1000 + i;
				map[i].compact_bitmap = &seen_map[i];
				ranges[i].container_id = containers[i] = key;
				ranges[i].plain_start = starts[i] = pattern == 2 ? n - i : key;
				ranges[i].stored_start = i;
				ranges[i].stored_size = 2000 + i;
				ranges[i].ends = &ranges[i].unit_count;
			}
			memcpy(original_map, map, sizeof(map));
			memcpy(original_ranges, ranges, sizeof(ranges));
			for (i = 1; i < n; i++)
			{
				grub_uint64_t id = ids[i], container = containers[i], start = starts[i];
				for (j = i; j && ids[j - 1] > id; j--)
					ids[j] = ids[j - 1];
				ids[j] = id;
				for (j = i; j && (containers[j - 1] > container ||
					(containers[j - 1] == container && starts[j - 1] > start)); j--)
				{
					containers[j] = containers[j - 1];
					starts[j] = starts[j - 1];
				}
				containers[j] = container;
				starts[j] = start;
			}
			grub_refs_sort_map(map, n);
			grub_refs_sort_compression(ranges, n);
			for (i = 0; i < n; i++)
			{
				unsigned m = (unsigned) map[i].start, r = (unsigned) ranges[i].stored_start;
				CHECK(map[i].id == ids[i]);
				CHECK(ranges[i].container_id == containers[i] && ranges[i].plain_start == starts[i]);
				CHECK(m < n && !seen_map[m] && memcmp(&map[i], &original_map[m], sizeof(map[i])) == 0);
				CHECK(r < n && !seen_ranges[r] && memcmp(&ranges[i], &original_ranges[r], sizeof(ranges[i])) == 0);
				if (m < n) seen_map[m] = 1;
				if (r < n) seen_ranges[r] = 1;
			}
		}
}

int main(void)
{
	int old=refs_review_main();
	lookup_cases(); extent_cases(); compression_cases(); map_growth_case(); sort_cases();
	printf("%s %u ReFS checks (%u new failures)\n", old || failures ? "FAIL":"PASS",checks,failures);
	return old || failures ? 1 : 0;
}
